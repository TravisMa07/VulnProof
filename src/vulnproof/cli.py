"""Local file IO and command presentation; ingestion itself has no IO."""

import argparse
import json
import os
import signal
import stat
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from .correlation import CorrelationFailure, correlate
from .correlation.engine import MAX_DOCUMENT_BYTES
from .ingest import ImportFailure, ingest_sarif
from .ingest.sarif import MAX_INPUT_BYTES
from .planning import PlanningFailure, create_plans
from .provenance import CaptureFailure, capture_source, verify_capture
from .runner import RunnerFailure, run_diagnostics
from .scanning import ScanFailure, scan_fixture, verify_scan
from .static import AnalysisFailure, analyze_capture


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
    args = parser.parse_args(argv)
    try:
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
        if args.command == "analyze":

            def terminate(signum: int, frame: object) -> None:
                raise KeyboardInterrupt

            previous = signal.signal(signal.SIGTERM, terminate)
            try:
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
    ) as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        if args.command == "scan-fixture":
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
        if args.command != "analyze":
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
