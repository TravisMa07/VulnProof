"""Authored pipeline/tool observations; real end-to-end acceptance is separate."""

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from tests.runner_support import IMAGE, fake_docker
from tests.static_pipeline import codeql_sarif, prepare, scanner_sarif
from tests.test_scanning import setup_scan

from vulnproof.correlation import correlate
from vulnproof.models import EvidenceBundle
from vulnproof.planning import create_plans
from vulnproof.runner import RunnerFailure
from vulnproof.runner.models import PreparedImage
from vulnproof.runner.profile import recipe_hash
from vulnproof.scanning import scan_fixture
from vulnproof.validation import validate
from vulnproof.validation.models import PROFILE, Driver, Preparation
from vulnproof.validation.preparation import approval, approval_bytes


def encoded(body: bytes) -> str:
    return base64.b64encode(body).decode()


def driver(*, positive: bool = True, failed_after_positive: bool = False) -> dict[str, Any]:
    marker = b"VulnProof:" + b"a" * 64 + b"\n"
    document = Path("fixtures/cwe22/data/downloads/example.txt").read_bytes()
    return dict(
        schema_version="1.0",
        profile=PROFILE,
        outcome="failed" if failed_after_positive else "completed",
        diagnostics_passed=True,
        control={"status": 200, "body_base64": encoded(document)},
        canary={
            "path": "/tmp/vulnproof/" + "b" * 32 + ".txt",
            "initially_absent": True,
            "body_base64": encoded(marker),
        },
        probes=[
            {
                "kind": kind,
                "status": 200 if positive else 404,
                "body_base64": encoded(marker if positive else b"not found"),
            }
            for kind in ("parent_traversal", "absolute_path")
        ][: 1 if failed_after_positive else 2],
        errors=["later_failure"] if failed_after_positive else [],
    )


def arguments(
    root: Path, *, controlled: bool = False, raw: bytes | None = None, scanner: bytes | None = None
) -> dict[str, Any]:
    scan = None
    if controlled:
        (root / "scanner").mkdir()
        source, scan, tool = setup_scan(root / "scanner")
        assert scan_fixture(source, scan, tool).outcome == "completed"
        scanner = (scan / "diagnostics/raw.sarif").read_bytes()
    (root / "pipeline").mkdir()
    capture, analysis = prepare(root / "pipeline", scanner=scanner, raw=raw)
    if scan is not None:
        capture = scan / "capture/snapshot"
    correlation = root / "correlation.json"
    correlation.write_text(correlate(capture, analysis).model_dump_json())
    plan = root / "plan.json"
    document = create_plans(capture, analysis, correlation)
    plan.write_text(document.model_dump_json())
    recipe = approval().recipes[0]
    assert document.correlation.snapshot.fingerprint is not None
    record = Preparation(
        schema_version="1.0",
        profile=PROFILE,
        approval_sha256=hashlib.sha256(approval_bytes()).hexdigest(),
        images=(
            PreparedImage(
                fixture_id=recipe.fixture_id,
                source_fingerprint=document.correlation.snapshot.fingerprint,
                recipe_sha256=recipe_hash(recipe),
                image_id=IMAGE,
            ),
        ),
    )
    preparation = root / "preparation.json"
    preparation.write_text(record.model_dump_json())
    return dict(
        capture=capture,
        analysis=analysis,
        correlation=correlation,
        plan=plan,
        preparation=preparation,
        finding_id=document.findings[0].finding_id,
        socket=root / "fake.sock",
        output=root / "attempt",
        authorize_validation=True,
        scan=scan,
    )


@pytest.mark.parametrize(
    "controlled,positive,expected",
    [(True, True, "confirmed"), (True, False, "inconclusive"), (False, True, "inconclusive")],
)
def test_classifications(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, controlled: bool, positive: bool, expected: str
) -> None:
    args = arguments(tmp_path, controlled=controlled)
    fake_docker(tmp_path, monkeypatch, validation_driver=driver(positive=positive))
    bundle = validate(**args)
    assert bundle.assessment is not None and bundle.assessment.classification == expected
    assert (
        EvidenceBundle.model_validate_json((args["output"] / "result.json").read_bytes()) == bundle
    )
    assert bundle.execution_evidence[0].oracle == ("observed" if positive else "not_observed")
    assert bundle.finding.source.state == ("matched" if controlled else "unverified")


@pytest.mark.parametrize(
    "control",
    [
        {"cleanup_failed": True},
        {"fail": "state"},
        {"exit": 1},
        {"oom": True},
        {"driver_failure": True},
    ],
)
def test_positive_survives_later_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, control: dict[str, Any]
) -> None:
    args = arguments(tmp_path, controlled=True)
    payload = driver(failed_after_positive=control.pop("driver_failure", False))
    fake_docker(tmp_path, monkeypatch, validation_driver=payload, **control)
    bundle = validate(**args)
    assert bundle.assessment is not None and bundle.assessment.classification == "failed"
    assert bundle.execution_evidence[0].oracle == "observed"


def test_diagnostics_preparation_is_rejected(tmp_path: Path) -> None:
    args = arguments(tmp_path)
    path = args["preparation"]
    data = json.loads(path.read_bytes())
    data["profile"] = "fixture-diagnostics-v1"
    path.write_text(json.dumps(data))
    with pytest.raises(RunnerFailure):
        validate(**args)
    assert not args["output"].exists()


def test_distinct_authorization(tmp_path: Path) -> None:
    args = arguments(tmp_path)
    args["authorize_validation"] = False
    with pytest.raises(RunnerFailure, match="authorization"):
        validate(**args)
    assert not args["output"].exists()


def test_alternative_paths_require_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = arguments(tmp_path, raw=codeql_sarif(alternatives=2))
    with pytest.raises(RunnerFailure, match="explicit path"):
        validate(**args)
    data = json.loads(args["plan"].read_bytes())
    selected = data["findings"][0]["plan"]["path_ids"][1]
    fake_docker(tmp_path, monkeypatch, validation_driver=driver())
    result = validate(**args, path_id=selected)
    assert result.assessment is not None and result.assessment.classification == "inconclusive"
    assert result.assessment.static_path_id == selected


@pytest.mark.parametrize(
    "scanner,raw,expected",
    [
        (scanner_sarif(rule="unsupported"), None, "unsupported"),
        (None, codeql_sarif(results=2), "inconclusive"),
    ],
)
def test_blocked_findings_never_run(
    tmp_path: Path, scanner: bytes | None, raw: bytes | None, expected: str
) -> None:
    args = arguments(tmp_path, scanner=scanner, raw=raw)
    result = validate(**args)
    assert result.assessment is not None and result.assessment.classification == expected
    assert result.execution_evidence[0].outcome == "not_run"
    assert not (args["output"] / "reservation.json").exists()


@pytest.mark.parametrize(
    "host", [{"NetworkMode": "bridge"}, {"ReadonlyRootfs": False}, {"Privileged": True}]
)
def test_policy_rejection_before_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: dict[str, Any]
) -> None:
    args = arguments(tmp_path)
    fake = fake_docker(tmp_path, monkeypatch, host_changes=host, validation_driver=driver())
    result = validate(**args)
    assert result.assessment is not None and result.assessment.classification == "failed"
    calls = [json.loads(line)["args"] for line in (fake / "calls.jsonl").read_text().splitlines()]
    assert not any(c[0] == "start" for c in calls)
    assert not json.loads((fake / "state.json").read_bytes())["exists"]


def test_control_failure_stops_probe_claims() -> None:
    payload = driver()
    payload["control"]["body_base64"] = encoded(b"wrong document")
    with pytest.raises(ValueError):
        Driver.model_validate_json(json.dumps(payload))
    payload["control"]["body_base64"] = encoded(
        Path("fixtures/cwe22/data/downloads/example.txt").read_bytes()
    )
    payload["canary"]["initially_absent"] = False
    with pytest.raises(ValueError):
        Driver.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "mode", ["timeout", "output", "interrupt", "changed_source", "changed_log"]
)
def test_operational_failure_classification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    from vulnproof.runner.docker import DockerClient

    args = arguments(tmp_path, controlled=True)
    fake = fake_docker(
        tmp_path,
        monkeypatch,
        validation_driver=driver(),
        driver_sleep=mode == "timeout",
        flood=mode == "output",
    )
    original = DockerClient.run

    def constrained(self: DockerClient, command: list[str], stage: str, **kwargs: Any) -> bytes:
        if stage == "start" and mode == "interrupt":
            raise KeyboardInterrupt
        if stage == "start" and mode == "timeout":
            kwargs["timeout"] = 0.05
        data = original(self, command, stage, **kwargs)
        if stage == "start" and mode == "changed_source":
            path = args["capture"] / "source/app.py"
            path.chmod(0o600)
            path.write_text("changed")
        if stage == "state" and mode == "changed_log":
            record = next(c for c in self.commands if c.stage == "start")
            (args["output"] / record.log.path).write_text("changed")
        return data

    monkeypatch.setattr(DockerClient, "run", constrained)
    if mode == "interrupt":
        with pytest.raises(KeyboardInterrupt):
            validate(**args)
        bundle = EvidenceBundle.model_validate_json((args["output"] / "result.json").read_bytes())
    else:
        bundle = validate(**args)
    assert bundle.assessment is not None and bundle.assessment.classification == "failed"
    assert not json.loads((fake / "state.json").read_bytes())["exists"]
    if mode in ("changed_source", "changed_log"):
        assert bundle.execution_evidence[0].oracle == "observed"


def test_cli_uses_distinct_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vulnproof.cli import main

    args = arguments(tmp_path, controlled=True)
    fake_docker(tmp_path, monkeypatch, validation_driver=driver())
    cli = ["validate"]
    for key in (
        "capture",
        "analysis",
        "correlation",
        "plan",
        "preparation",
        "finding_id",
        "socket",
        "output",
        "scan",
    ):
        flag = "docker-socket" if key == "socket" else key.replace("_", "-")
        cli += ["--" + flag, str(args[key])]
    assert main(cli) == 2
    assert not args["output"].exists()
    assert main([*cli, "--authorize-validation"]) == 0
    assert '"classification": "confirmed"' in capsys.readouterr().out
    assert main([*cli, "--authorize-validation"]) == 2


def test_changed_image_and_plan_rejected(tmp_path: Path) -> None:
    args = arguments(tmp_path)
    path = args["preparation"]
    data = json.loads(path.read_bytes())
    data["images"][0]["source_fingerprint"] = "0" * 64
    path.write_text(json.dumps(data))
    with pytest.raises(RunnerFailure):
        validate(**args)
    assert not args["output"].exists()
    (args["plan"]).write_text("changed")
    with pytest.raises(RunnerFailure):
        validate(**args)


def test_control_failure_report_is_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = arguments(tmp_path, controlled=True)
    payload = driver()
    payload.update(outcome="failed", canary=None, probes=[], errors=["control_failed"])
    payload["control"]["body_base64"] = encoded(b"unexpected")
    fake_docker(tmp_path, monkeypatch, validation_driver=payload)
    result = validate(**args)
    assert result.assessment is not None and result.assessment.classification == "failed"
    assert result.execution_evidence[0].oracle == "not_evaluated"


def test_analysis_failure_is_failed_without_execution(tmp_path: Path) -> None:
    from vulnproof.static.models import AnalysisDocument

    args = arguments(tmp_path)
    path = args["analysis"] / "analysis.json"
    document = json.loads(path.read_bytes())
    document.update(
        outcome="failed",
        normalization="not_attempted",
        results=[],
        diagnostics=[{"code": "authored_analysis_failure", "message": "Authored analysis failure"}],
    )
    # Recreate coherent authored failure observations, rather than corrupting a live report.
    document["source"]["state"] = "unverified"
    document["source"]["observed_snapshot_id"] = None
    path.write_text(AnalysisDocument.model_validate_json(json.dumps(document)).model_dump_json())
    args["correlation"].write_text(correlate(args["capture"], args["analysis"]).model_dump_json())
    args["plan"].write_text(
        create_plans(args["capture"], args["analysis"], args["correlation"]).model_dump_json()
    )
    result = validate(**args)
    assert result.assessment is not None and result.assessment.classification == "failed"
    assert result.execution_evidence[0].outcome == "not_run"


@pytest.mark.parametrize(
    "status,body", [(404, b"marker"), (200, b"prefix"), (200, b"suffix"), (200, b"reflected-name")]
)
def test_oracle_requires_exact_body_and_status(status: int, body: bytes) -> None:
    payload = driver()
    marker = base64.b64decode(payload["canary"]["body_base64"])
    replacement = (
        marker
        if body == b"marker"
        else b"prefix" + marker
        if body == b"prefix"
        else marker + b"suffix"
        if body == b"suffix"
        else payload["canary"]["path"].encode()
    )
    for probe in payload["probes"]:
        probe.update(status=status, body_base64=encoded(replacement))
    assert not Driver.model_validate_json(json.dumps(payload)).observed
