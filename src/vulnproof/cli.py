"""Local file IO and command presentation; ingestion itself has no IO."""

import argparse
import json
import os
import signal
import stat
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from .correlation import CorrelationFailure, correlate
from .correlation.engine import MAX_DOCUMENT_BYTES
from .correlation.repository import correlate_repository, prepare_import, prepare_inventory
from .discovery.repository import discover
from .ingest import ImportFailure, ingest_sarif
from .ingest.sarif import MAX_INPUT_BYTES
from .intake import inventory
from .planning import PlanningFailure, create_plans
from .provenance import CaptureFailure, capture_source, verify_capture
from .reporting import ReportFailure, write_report
from .runner import RunnerFailure, run_diagnostics
from .scanning import ScanFailure, scan_fixture, verify_scan
from .scanning.repository import scan_repository
from .static import AnalysisFailure, analyze_capture
from .static.repository import investigate
from .validation import validate


def _read_input(path: Path) -> bytes:
    # Nonblocking open lets us reject FIFOs/devices instead of waiting for a writer.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ImportFailure("invalid_input_file", "SARIF input must be a regular file")
        return stream.read(MAX_INPUT_BYTES + 1)


def _publish(path: Path, content: str) -> None:
    """Publish one complete file with no overwrite, including competing writers."""
    descriptor, temporary = tempfile.mkstemp(prefix=".vulnproof-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        # Same-directory hard link is atomic and fails if any destination exists.
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnproof", description="Investigate scanner findings")
    commands = parser.add_subparsers(dest="command", required=True)
    intake = commands.add_parser("intake", help="Inventory SARIF results against a local checkout")
    intake.add_argument("--component", help="Optional repository-relative path prefix")
    for flag in ("repo", "sarif", "output"):
        intake.add_argument("--" + flag, type=Path, required=True)
    ingest = commands.add_parser("ingest", help="Import local Semgrep SARIF 2.1.0")
    ingest.add_argument(
        "--sarif", type=Path, required=True, help="Existing SARIF file (10 MiB max)"
    )
    ingest.add_argument("--output", type=Path, required=True, help="New self-contained JSON file")
    capture = commands.add_parser(
        "capture", help="Capture bounded source with unverified scanner provenance"
    )
    capture.add_argument("--ingestion", type=Path, required=True)
    capture.add_argument("--source-root", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True, help="New directory outside source")
    capture.add_argument(
        "--expected-commit", help="Require the captured scope to match this full commit ID"
    )
    verify = commands.add_parser("verify-source", help="Rehash an existing capture before using it")
    verify.add_argument(
        "--capture", type=Path, required=True, help="Published output/snapshot directory"
    )
    prepare = commands.add_parser(
        "prepare-repository", help="Capture checkout and inventory an existing SARIF report"
    )
    prepare.add_argument("--component")
    import_source = prepare.add_mutually_exclusive_group(required=True)
    import_source.add_argument("--sarif", type=Path)
    import_source.add_argument(
        "--inventory", type=Path, help="Existing intake inventory with embedded SARIF"
    )
    for flag in ("repo", "output"):
        prepare.add_argument("--" + flag, type=Path, required=True)
    links = commands.add_parser(
        "correlate-repository", help="Link repository findings to retained CodeQL paths"
    )
    for flag in ("scan", "investigation", "output"):
        links.add_argument("--" + flag, type=Path, required=True)
    discovery = commands.add_parser(
        "discover-repository", help="Discover application routes and inputs for correlated paths"
    )
    for flag in ("scan", "investigation", "correlation", "output"):
        discovery.add_argument("--" + flag, type=Path, required=True)
    investigation = commands.add_parser(
        "investigate", help="Trace modeled paths in a repository scan snapshot"
    )
    for flag in ("scan", "output", "codeql-bundle"):
        investigation.add_argument("--" + flag, type=Path, required=True)
    analyze = commands.add_parser(
        "analyze", help="Analyze an approved fixture capture with pinned CodeQL"
    )
    analyze.add_argument("--capture", type=Path, required=True)
    analyze.add_argument("--output", type=Path, required=True, help="New analysis directory")
    analyze.add_argument(
        "--codeql-bundle",
        type=Path,
        required=True,
        help="Trusted prepared directory containing the CodeQL executable",
    )
    correlation = commands.add_parser("correlate", help="Link findings to candidate static paths")
    correlation.add_argument("--capture", type=Path, required=True)
    correlation.add_argument("--analysis", type=Path, required=True)
    correlation.add_argument("--output", type=Path, required=True, help="New correlation JSON file")
    planning = commands.add_parser(
        "plan", help="Describe draft fixture tests without executing them"
    )
    planning.add_argument("--capture", type=Path, required=True)
    planning.add_argument("--analysis", type=Path, required=True)
    planning.add_argument("--correlation", type=Path, required=True)
    planning.add_argument("--output", type=Path, required=True, help="New planning JSON file")
    runner = commands.add_parser(
        "check-runner", help="Run authorized fixture diagnostics, not vulnerability probes"
    )
    for name in (
        "capture",
        "analysis",
        "correlation",
        "plan",
        "prepared-images",
        "docker-socket",
        "output",
    ):
        runner.add_argument("--" + name, type=Path, required=True)
    runner.add_argument("--finding-id", required=True)
    runner.add_argument(
        "--authorize-execution",
        action="store_true",
        help="Authorize only the reviewed fixture diagnostic operation",
    )
    repository = commands.add_parser("scan", help="Scan a checkout with the reviewed Semgrep rules")
    repository.add_argument("--component", help="Optional repository-relative directory")
    for flag in ("repo", "semgrep-environment", "output"):
        repository.add_argument("--" + flag, type=Path, required=True)
    scan = commands.add_parser("scan-fixture", help="Run pinned Semgrep on reviewed fixture bytes")
    scan.add_argument("--source-root", type=Path, required=True)
    scan.add_argument("--semgrep-environment", type=Path, required=True)
    scan.add_argument("--output", type=Path, required=True, help="New controlled-scan directory")
    verify_scan_parser = commands.add_parser(
        "verify-scan", help="Recheck scan evidence and derive matched finding records"
    )
    verify_scan_parser.add_argument("--scan", type=Path, required=True)
    verify_scan_parser.add_argument(
        "--output", type=Path, required=True, help="New association JSON file"
    )
    validation = commands.add_parser(
        "validate", help="Authorize reviewed CWE-22 fixture validation"
    )
    for argument in (
        "capture",
        "analysis",
        "correlation",
        "plan",
        "preparation",
        "output",
        "docker-socket",
    ):
        validation.add_argument("--" + argument, type=Path, required=True)
    validation.add_argument(
        "--scan", type=Path, help="Optional controlled scan; required for confirmation"
    )
    validation.add_argument("--finding-id", required=True)
    validation.add_argument(
        "--path-id", help="Required when the unique candidate has multiple paths"
    )
    validation.add_argument("--authorize-validation", action="store_true")
    report_parser = commands.add_parser(
        "report", help="Render offline JSON/HTML from retained validation evidence"
    )
    report_parser.add_argument(
        "--validation", type=Path, required=True, help="Directory containing result.json"
    )
    report_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New report directory outside validation evidence",
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare-repository":
            if args.inventory:
                prepare_inventory(args.repo, args.component, args.inventory, args.output)
            else:
                prepare_import(args.repo, args.component, _read_input(args.sarif), args.output)
            return 0
        if args.command in ("correlate-repository", "discover-repository"):
            if any(
                args.output.resolve().is_relative_to(root.resolve())
                for root in (args.scan, args.investigation)
            ):
                raise CorrelationFailure(
                    "invalid_output", "Choose a new output file outside both evidence directories"
                )
            if args.command == "discover-repository":
                content = discover(args.scan, args.investigation, args.correlation)
            else:
                content = correlate_repository(args.scan, args.investigation)
            _publish(args.output, content)
            return 0
        if args.command == "scan":
            outcome = scan_repository(
                args.repo, args.component, args.output, args.semgrep_environment
            )
            print(json.dumps({"status": outcome, "receipt": str(args.output / "scan.json")}))
            return int(outcome != "completed")
        if args.command == "intake":
            inv = inventory(_read_input(args.sarif), args.repo, args.component)
            content = json.dumps(asdict(inv), ensure_ascii=False, indent=2) + "\n"
            if len(content.encode()) > MAX_DOCUMENT_BYTES:
                raise ImportFailure("inventory_limit", "Inventory exceeds 64 MiB")
            _publish(args.output, content)
            print(
                json.dumps(
                    {"status": inv.status, "results": inv.result_count, "runs": len(inv.runs)}
                )
            )
            return int(inv.status == "partial")
        if args.command == "report":
            report_document = write_report(args.validation, args.output)
            print(
                json.dumps(
                    {
                        "status": "completed",
                        "recorded_assessment": report_document.evidence.assessment.classification
                        if report_document.evidence.assessment
                        else None,
                        "artifact_integrity": report_document.integrity,
                        "outputs": ["report.json", "report.html"],
                    }
                )
            )
            return (
                0
                if report_document.integrity == "verified"
                and all(d.status == "available" for d in report_document.runtime)
                else 1
            )
        if args.command == "validate":

            def stop_validation(signum: int, frame: object) -> None:
                raise KeyboardInterrupt

            previous = signal.signal(signal.SIGTERM, stop_validation)
            try:
                bundle = validate(
                    capture=args.capture,
                    analysis=args.analysis,
                    correlation=args.correlation,
                    plan=args.plan,
                    preparation=args.preparation,
                    finding_id=args.finding_id,
                    socket=args.docker_socket,
                    output=args.output,
                    authorize_validation=args.authorize_validation,
                    scan=args.scan,
                    path_id=args.path_id,
                )
            finally:
                signal.signal(signal.SIGTERM, previous)
            assert bundle.assessment is not None
            print(
                json.dumps(
                    {"classification": bundle.assessment.classification, "result": "result.json"}
                )
            )
            return 1 if bundle.assessment.classification == "failed" else 0
        if args.command == "scan-fixture":

            def stop_scan(signum: int, frame: object) -> None:
                raise KeyboardInterrupt

            previous = signal.signal(signal.SIGTERM, stop_scan)
            try:
                receipt = scan_fixture(args.source_root, args.output, args.semgrep_environment)
            finally:
                signal.signal(signal.SIGTERM, previous)
            print(
                json.dumps(
                    {
                        "outcome": receipt.outcome,
                        "fixture": receipt.fixture_id,
                        "capture": "capture/snapshot" if receipt.snapshot else None,
                    }
                )
            )
            return 0 if receipt.outcome == "completed" else 1
        if args.command == "verify-scan":
            destination = args.output.parent.resolve() / args.output.name
            if destination.is_relative_to(args.scan.resolve()):
                raise ScanFailure(
                    "invalid_output", "Association output must be outside the retained scan"
                )
            associations = verify_scan(args.scan)
            content = associations.model_dump_json(indent=2) + "\n"
            if len(content.encode("utf-8")) > MAX_DOCUMENT_BYTES:
                raise ScanFailure("association_limit", "Association output exceeds 64 MiB")
            _publish(args.output, content)
            print(
                json.dumps(
                    {
                        "status": "source_associated",
                        "findings": len(associations.findings),
                        "snapshot": associations.snapshot.id,
                    }
                )
            )
            return 0
        if args.command == "check-runner":

            def stop_runner(signum: int, frame: object) -> None:
                raise KeyboardInterrupt

            previous = signal.signal(signal.SIGTERM, stop_runner)
            try:
                attempt = run_diagnostics(
                    capture=args.capture,
                    analysis=args.analysis,
                    correlation=args.correlation,
                    plan=args.plan,
                    preparation=args.prepared_images,
                    finding_id=args.finding_id,
                    socket=args.docker_socket,
                    output=args.output,
                    authorize_execution=args.authorize_execution,
                )
            finally:
                signal.signal(signal.SIGTERM, previous)
            print(
                json.dumps(
                    {
                        "execution": attempt.execution,
                        "cleanup": attempt.cleanup,
                        "policy_verified": attempt.policy_verified,
                    }
                )
            )
            return (
                0
                if attempt.execution == "completed" and attempt.cleanup == "verified_absent"
                else 1
            )
        if args.command == "plan":
            destination = args.output.parent.resolve() / args.output.name
            if (
                any(
                    destination.is_relative_to(root.resolve())
                    for root in (args.capture, args.analysis)
                )
                or destination == args.correlation.resolve()
            ):
                raise PlanningFailure(
                    "invalid_output",
                    "Output must be outside evidence directories and differ from correlation input",
                )
            planning_report = create_plans(args.capture, args.analysis, args.correlation)
            _publish(args.output, planning_report.model_dump_json(indent=2) + "\n")
            print(
                json.dumps(
                    {
                        "status": "completed",
                        "drafts": sum(f.disposition == "draft" for f in planning_report.findings),
                        "blocked": sum(
                            f.disposition == "blocked" for f in planning_report.findings
                        ),
                        "execution_authorized": False,
                    }
                )
            )
            return 0
        if args.command == "correlate":
            # Keep publication outside retained evidence, including through parent symlinks.
            destination = args.output.parent.resolve() / args.output.name
            if any(
                destination.is_relative_to(root.resolve()) for root in (args.capture, args.analysis)
            ):
                raise CorrelationFailure(
                    "invalid_output", "Output must be outside input directories"
                )
            correlation_report = correlate(args.capture, args.analysis)
            content = correlation_report.model_dump_json(indent=2) + "\n"
            if len(content.encode("utf-8")) > MAX_DOCUMENT_BYTES:
                raise CorrelationFailure("correlation_limit", "Correlation JSON exceeds 64 MiB")
            _publish(args.output, content)
            print(
                json.dumps(
                    {
                        "status": "completed",
                        "findings": len(correlation_report.findings),
                        "candidate_results": sum(
                            len(f.candidates) for f in correlation_report.findings
                        ),
                    }
                )
            )
            return 0
        if args.command in ("analyze", "investigate"):

            def terminate(signum: int, frame: object) -> None:
                raise KeyboardInterrupt

            previous = signal.signal(signal.SIGTERM, terminate)
            try:
                if args.command == "investigate":
                    investigation_report = investigate(args.scan, args.output, args.codeql_bundle)
                    print(investigation_report.model_dump_json(include={"outcome", "diagnostics"}))
                    return int(investigation_report.outcome != "completed")
                report = analyze_capture(args.capture, args.output, args.codeql_bundle)
            finally:
                signal.signal(signal.SIGTERM, previous)
            for reason in report.diagnostics:
                print(f"{reason.code}: {reason.message}", file=sys.stderr)
            for result in report.results:
                for reason in result.diagnostics:
                    print(f"{reason.code}: {reason.message}", file=sys.stderr)
            print(
                json.dumps(
                    {
                        "outcome": report.outcome,
                        "normalization": report.normalization,
                        "results": len(report.results),
                        "paths": sum(len(r.paths) for r in report.results),
                    }
                )
            )
            return 0 if report.outcome == "completed" and report.normalization == "complete" else 1
        if args.command == "verify-source":
            provenance = verify_capture(args.capture)
            print(json.dumps({"status": "content_verified", "snapshot": provenance.snapshot.id}))
            return 0
        if args.command == "capture":
            provenance = capture_source(
                args.ingestion, args.source_root, args.output, expected_commit=args.expected_commit
            )
            partial = any(b.location != "present" for b in provenance.bindings) or any(
                d.code == "ingestion_partial" for d in provenance.diagnostics
            )
            for reason in provenance.diagnostics:
                print(f"{reason.code}: {reason.message}", file=sys.stderr)
            for binding in provenance.bindings:
                for reason in binding.reasons:
                    print(f"{reason.code}: {reason.message}", file=sys.stderr)
            print(
                json.dumps(
                    {
                        "status": "partial" if partial else "complete",
                        "snapshot": provenance.snapshot.id,
                        "files": len(provenance.files),
                        "unverified_bindings": len(provenance.bindings),
                    }
                )
            )
            return 1 if partial else 0
        document = ingest_sarif(_read_input(args.sarif))
        _publish(args.output, document.model_dump_json(indent=2) + "\n")
    except (
        ImportFailure,
        CaptureFailure,
        AnalysisFailure,
        CorrelationFailure,
        PlanningFailure,
        RunnerFailure,
        ScanFailure,
        ReportFailure,
    ) as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        if args.command == "validate":
            print(
                "validation_interrupted: Cleanup attempted; retain attempt and reservation for recovery",
                file=sys.stderr,
            )
            return 130
        if args.command in ("scan", "scan-fixture"):
            print(
                "scan_interrupted: Scanner stopped; see retained failed receipt where available",
                file=sys.stderr,
            )
            return 130
        if args.command == "check-runner":
            print(
                "runner_interrupted: Cleanup attempted; see attempt report and reservation",
                file=sys.stderr,
            )
            return 130
        if args.command not in ("analyze", "investigate"):
            raise
        print(
            "analysis_interrupted: Process group stopped; retained report is failed",
            file=sys.stderr,
        )
        return 130
    except FileExistsError:
        print("output_exists: Refusing to overwrite an existing output", file=sys.stderr)
        return 2
    except OSError as exc:
        # Do not echo untrusted paths/control characters from OS exception messages.
        print(
            f"file_error: Unable to read input or publish output (errno {exc.errno})",
            file=sys.stderr,
        )
        return 2
    for diagnostic in document.diagnostics:
        print(
            f"{diagnostic.severity}: {diagnostic.code} {diagnostic.pointer}: {diagnostic.message}",
            file=sys.stderr,
        )
    print(
        json.dumps(
            {
                "status": document.status,
                "imported": len(document.findings),
                "results": document.result_count,
                "diagnostics": len(document.diagnostics),
            }
        )
    )
    return 1 if document.status == "partial" else 0
