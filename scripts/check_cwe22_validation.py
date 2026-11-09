"""Actual scanner/static/validation workflow plus independent patched-driver checks."""

import argparse
from pathlib import Path
from uuid import uuid4

from vulnproof.correlation import correlate
from vulnproof.planning import create_plans
from vulnproof.scanning import scan_fixture
from vulnproof.static import analyze_capture
from vulnproof.validation import validate
from vulnproof.validation.models import Attempt, Preparation
from vulnproof.validation.preparation import select_image
from vulnproof.validation.runtime import execute

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-socket", type=Path, required=True)
    parser.add_argument("--preparation", type=Path, required=True)
    args = parser.parse_args()
    root = ROOT / ".cache/validation-check" / uuid4().hex
    root.mkdir(parents=True)
    print(f"Artifacts: {root}", flush=True)
    scan = root / "scan"
    if (
        scan_fixture(
            ROOT / "fixtures/cwe22/vulnerable", scan, ROOT / ".cache/semgrep/1.184.0"
        ).outcome
        != "completed"
    ):
        raise SystemExit("FAIL scanner; see retained scan receipt")
    capture = scan / "capture/snapshot"
    analysis = root / "analysis"
    report = analyze_capture(capture, analysis, ROOT / ".cache/codeql/2.27.3/codeql")
    if report.outcome != "completed" or report.normalization != "complete":
        raise SystemExit("FAIL static analysis; see analysis.json")
    correlation = root / "correlation.json"
    correlated = correlate(capture, analysis)
    correlation.write_text(correlated.model_dump_json(indent=2))
    plan = root / "plan.json"
    planned = create_plans(capture, analysis, correlation)
    plan.write_text(planned.model_dump_json(indent=2))
    if len(planned.findings) != 1 or planned.findings[0].plan is None:
        raise SystemExit("FAIL: expected one real eligible vulnerable finding")
    first = validate(
        capture=capture,
        analysis=analysis,
        correlation=correlation,
        plan=plan,
        preparation=args.preparation,
        finding_id=planned.findings[0].finding_id,
        socket=args.docker_socket,
        output=root / "vulnerable",
        authorize_validation=True,
        scan=scan,
    )
    if first.assessment is None or first.assessment.classification != "confirmed":
        raise SystemExit("FAIL: actual source-bound vulnerable workflow did not confirm")
    print(
        "PASS actual Semgrep -> CodeQL -> planning -> restricted validation -> confirmed",
        flush=True,
    )
    second = validate(
        capture=capture,
        analysis=analysis,
        correlation=correlation,
        plan=plan,
        preparation=args.preparation,
        finding_id=planned.findings[0].finding_id,
        socket=args.docker_socket,
        output=root / "unverified-source",
        authorize_validation=True,
    )
    first_attempt = Attempt.model_validate_json((root / "vulnerable/attempt.json").read_bytes())
    second_attempt = Attempt.model_validate_json(
        (root / "unverified-source/attempt.json").read_bytes()
    )
    if (
        second.assessment is None
        or second.assessment.classification != "inconclusive"
        or second.execution_evidence[0].oracle != "observed"
        or first_attempt.driver is None
        or second_attempt.driver is None
        or first_attempt.driver.canary is None
        or second_attempt.driver.canary is None
        or first_attempt.driver.canary.body == second_attempt.driver.canary.body
        or first_attempt.attempt_id == second_attempt.attempt_id
    ):
        raise SystemExit("FAIL: fresh-container canary or unverified-source gate")
    print("PASS fresh canary/container and observed-but-unverified inconclusive result", flush=True)
    # Exercise the patched driver independently: no fake patched finding or assessment.
    data = args.preparation.read_bytes()
    prepared = Preparation.model_validate_json(data)
    image = next(i for i in prepared.images if i.fixture_id == "cwe22-patched-v1")
    select_image(prepared, image.fixture_id, image.source_fingerprint)
    output = root / "patched-driver-only"
    output.mkdir(mode=0o700)
    (output / "diagnostics").mkdir()
    attempt = execute(
        image=image,
        prepared=prepared,
        preparation_data=data,
        plan_data=b"development-driver-check-only-no-finding",
        finding_id="development:driver-only",
        candidate_id="development:no-candidate",
        path_id="development:no-path",
        socket=args.docker_socket,
        output=output,
        authorize_validation=True,
    )
    if (
        attempt.execution != "completed"
        or attempt.cleanup != "verified_absent"
        or attempt.driver is None
        or attempt.driver.observed
        or any(p.status != 404 for p in attempt.driver.probes)
    ):
        raise SystemExit("FAIL: patched driver control/probes/cleanup")
    print("PASS patched driver: valid control, both probes 404, no assessment emitted", flush=True)


if __name__ == "__main__":
    main()
