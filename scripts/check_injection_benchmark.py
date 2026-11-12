"""Opt-in repeatable injection benchmark; all application imports occur inside Docker."""

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from vulnproof.injections.models import ValidationRequest
from vulnproof.injections.planning import plan_injections
from vulnproof.injections.reporting import write_injection_report
from vulnproof.injections.runtime import validate_injection
from vulnproof.investigation.assessment import ValidationEvidence, assess
from vulnproof.investigation.capabilities import INJECTION_QUERIES
from vulnproof.investigation.contracts import HttpInvocation
from vulnproof.onboarding.planning import inspect_application
from vulnproof.onboarding.preparation import prepare_application
from vulnproof.onboarding.runtime import exercise_application
from vulnproof.runner.docker import RunnerFailure
from vulnproof.scanning.repository import scan_repository
from vulnproof.static.repository import investigate
from vulnproof.validation.registry import VALIDATORS

KINDS = ("command", "sql", "template")


def application_profile(kind: str, variant: str, wheelhouse: Path) -> dict[str, Any]:
    wheels = [
        {"filename": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        for p in sorted(wheelhouse.glob("*.whl"))
    ]
    if not wheels:
        raise ValueError("Prepare the pinned Linux Flask wheelhouse first")
    profile: dict[str, Any] = dict(
        schema_version="1.0",
        kind="http",
        command=["python", "app.py"],
        workdir=f"{kind}/{variant}",
        wheels=wheels,
        readiness={"target": "/ready", "status": 200},
        controls=[
            {
                "target": "/test?value=reader",
                "expected_status": 200,
                "expected_body_sha256": hashlib.sha256(b"reader").hexdigest(),
            }
        ],
    )
    if kind == "sql":
        profile["initialize"] = [
            [
                "python",
                "-c",
                "import os,sqlite3; d=sqlite3.connect(os.environ['VULNPROOF_STATE_DIR']+'/data.db'); d.execute('CREATE TABLE records(name TEXT, value TEXT)'); d.executemany('INSERT INTO records VALUES(?,?)',[('reader','reader'),('protected',os.environ['VULNPROOF_VALIDATION_MARKER'])]); d.commit()",
            ]
        ]
    return profile


def endpoint(kind: str, variant: str) -> dict[str, Any]:
    return dict(
        capability=kind,
        file=f"{kind}/{variant}/app.py",
        handler="exercise",
        request=dict(
            schema_version="1.0",
            route="/test",
            query_key="value",
            fixed_query=[],
            control_value="reader",
        ),
        control_sha256=hashlib.sha256(b"reader").hexdigest(),
        synthetic_sql_state=kind == "sql",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "fixtures",
        "semgrep-environment",
        "codeql-bundle",
        "wheelhouse",
        "docker-socket",
        "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--authorize-preparation", action="store_true")
    parser.add_argument("--authorize-validation", action="store_true")
    parser.add_argument("--runs", type=int, choices=(1, 3), default=3)
    args = parser.parse_args()
    if not args.authorize_preparation or not args.authorize_validation:
        parser.error("Review fixtures and authorize both preparation and validation explicitly")
    root = args.output.absolute()
    root.mkdir(mode=0o700)
    checkout = root / "checkout"
    checkout.mkdir()
    for kind in KINDS:
        for variant in ("vulnerable", "patched"):
            source = args.fixtures / kind / variant / "app.py"
            if source.is_symlink() or not source.is_file():
                raise ValueError("Expected reviewed regular app.py files")
            target = checkout / kind / variant
            target.mkdir(parents=True)
            shutil.copyfile(source, target / "app.py")
    scan = root / "scan"
    if scan_repository(checkout, None, scan, args.semgrep_environment) != "completed":
        raise RunnerFailure(
            "incomplete_scan", "Benchmark requires complete actual scanner evidence"
        )
    investigations = {}
    static_counts = {}
    for kind in KINDS:
        path = root / ("analysis-" + kind)
        result = investigate(scan, path, args.codeql_bundle, INJECTION_QUERIES[kind])
        if result.outcome != "completed":
            raise RunnerFailure(
                "incomplete_analysis", "Benchmark requires actual complete CodeQL analysis"
            )
        investigations[kind] = path
        static_counts[kind] = {
            variant: sum(
                r.sink is not None and r.sink.path == f"{kind}/{variant}/app.py" and bool(r.paths)
                for r in result.results
            )
            for variant in ("vulnerable", "patched")
        }
        if static_counts[kind]["vulnerable"] < 1:
            raise RunnerFailure("static_feasibility_failed", "Missing expected vulnerable path")
    config = root / "injections.json"
    config.write_text(
        json.dumps(
            dict(
                schema_version="1.0",
                endpoints=[endpoint(k, v) for k in KINDS for v in ("vulnerable", "patched")],
            ),
            indent=2,
        )
    )
    plans = plan_injections(scan, investigations, config)
    plan = root / "plans.json"
    plan.write_text(plans.model_dump_json(indent=2))
    summaries = []
    validations = []
    for kind in KINDS:
        for variant in ("vulnerable", "patched"):
            case = root / f"{kind}-{variant}"
            case.mkdir()
            appconfig = case / "application.json"
            appconfig.write_text(
                json.dumps(application_profile(kind, variant, args.wheelhouse), indent=2)
            )
            onboarding = case / "onboarding.json"
            onboarding.write_text(inspect_application(scan, appconfig).model_dump_json(indent=2))
            preparation = case / "preparation"
            prepare_application(
                scan=scan,
                plan=onboarding,
                config=appconfig,
                wheelhouse=args.wheelhouse,
                socket=args.docker_socket,
                output=preparation,
                authorize_preparation=True,
            )
            selected = next(
                (
                    e
                    for e in plans.entries
                    if e.capability == kind
                    and e.endpoint
                    and e.endpoint.file == f"{kind}/{variant}/app.py"
                ),
                None,
            )
            if variant == "vulnerable" and (selected is None or selected.status != "draft"):
                raise ValueError("Vulnerable benchmark requires a real source-bound draft")
            for run in range(args.runs):
                output = case / f"run-{run + 1}"
                if selected is not None:
                    validated = validate_injection(
                        scan=scan,
                        investigations=investigations,
                        config=config,
                        plan=plan,
                        finding_id=selected.finding_id,
                        onboarding=onboarding,
                        application_config=appconfig,
                        preparation=preparation / "prepared-application.json",
                        socket=args.docker_socket,
                        output=output,
                        authorize_validation=True,
                    )
                    observed = validated.decision
                    attempt = validated.attempt
                    if run == 0:
                        validations.append(output)
                    level = "source_bound_validation"
                else:
                    # No invented SAST findings or paths for patched fixtures. Exercise the
                    # exact oracle as a dynamic regression, distinct from a pipeline verdict.
                    request = ValidationRequest.model_validate_json(
                        json.dumps(
                            {
                                k: v
                                for k, v in endpoint(kind, variant).items()
                                if k in ("capability", "request", "control_sha256")
                            }
                        )
                    )
                    attempt = exercise_application(
                        scan=scan,
                        plan=onboarding,
                        config=appconfig,
                        preparation=preparation / "prepared-application.json",
                        socket=args.docker_socket,
                        output=output,
                        authorize_execution=True,
                        validation=request,
                    )
                    observed = assess(
                        f"{kind}-injection-v1",
                        ValidationEvidence(
                            execution=attempt.outcome,
                            policy_verified=attempt.policy_verified,
                            cleanup="verified_absent"
                            if attempt.cleanup and all(attempt.cleanup.values())
                            else "unverified",
                            control_valid=bool(
                                attempt.observation
                                and isinstance(attempt.observation.get("validation"), dict)
                                and attempt.observation["validation"].get("control_valid")
                            ),
                            scanner_source_state="controlled_snapshot",
                            invocation=HttpInvocation(
                                request_target=request.request.target("reader"),
                                input_location="query",
                                input_name="value",
                                request_profile=request.request,
                                expected_body_sha256=request.control_sha256,
                            ),
                            observations=attempt.observation,
                        ),
                        VALIDATORS,
                    )
                    level = "dynamic_oracle_regression_not_finding_confirmation"
                clean = bool(attempt and attempt.cleanup and all(attempt.cleanup.values()))
                expected = "confirmed" if variant == "vulnerable" else "inconclusive"
                passed = (
                    observed.classification == expected
                    and clean
                    and bool(attempt and attempt.outcome == "completed")
                )
                summaries.append(
                    dict(
                        capability=kind,
                        variant=variant,
                        run=run + 1,
                        evidence_level=level,
                        classification=observed.classification,
                        reason=observed.reason,
                        cleanup=clean,
                        passed=passed,
                    )
                )
                print(json.dumps(summaries[-1]), flush=True)
    # Select one run explicitly per finding; repeatability remains in benchmark.json.
    write_injection_report(
        scan=scan,
        investigations=investigations,
        config=config,
        plan=plan,
        validations=tuple(validations),
        output=root / "report",
    )
    summary = dict(
        schema_version="1.0",
        profile="injection-benchmark-v1",
        runs=args.runs,
        static_counts=static_counts,
        findings=len(plans.entries),
        drafts=sum(e.status == "draft" for e in plans.entries),
        attempts=summaries,
        passed=all(s["passed"] for s in summaries),
    )
    (root / "benchmark.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
