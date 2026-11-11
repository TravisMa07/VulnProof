import json
from pathlib import Path
from typing import Any

import pytest
from tests.repository_control_support import control_inputs
from tests.test_repository_controls import setup

from vulnproof.cli import main
from vulnproof.reporting.prepare import ReportFailure
from vulnproof.reporting.repository import write_repository_report
from vulnproof.validation.repository import validate_repository


def inputs(args: dict[str, Any]) -> dict[str, Any]:
    return {
        k: args[k] for k in ("scan", "investigation", "correlation", "discovery", "plan", "config")
    }


def test_inventory_without_execution_and_offline_html(tmp_path: Path) -> None:
    args = control_inputs(tmp_path, mode="import_failed")
    report = write_repository_report(**inputs(args), validations=(), output=tmp_path / "report")
    assert report.integrity == "verified"
    assert len(report.plan["findings"]) == 1
    html = (tmp_path / "report/report.html").read_text()
    for phrase in (
        "not tested in this report",
        "Modeled static flow",
        "exports/web.py:6",
        "CodeQL",
        "Observed container behavior",
        "Content-Security-Policy",
    ):
        assert phrase in html
    assert "<script" not in html
    assert 'src="http' not in html
    with pytest.raises(ReportFailure):
        write_repository_report(**inputs(args), validations=(), output=tmp_path / "report")


def test_attempts_are_not_combined(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args, _ = setup(tmp_path, monkeypatch)
    args.pop("authorize_execution")
    result = validate_repository(**args, authorize_validation=True)
    assert result.classification == "failed"
    first = args["output"]
    args["output"] = tmp_path / "second"
    validate_repository(**args, authorize_validation=True)
    report = write_repository_report(
        **inputs(args), validations=(first, args["output"]), output=tmp_path / "report"
    )
    assert report.integrity == "verified"
    assert len(report.validations) == 2
    assert all(d.result and d.result.classification == "failed" for d in report.validations)
    html = (tmp_path / "report/report.html").read_text()
    assert "Attempt 1" in html and "Attempt 2" in html
    assert "2 retained validation result(s)" in html


@pytest.mark.parametrize(
    "change", ["source", "plan", "missing_log", "changed_log", "missing_analysis"]
)
def test_integrity_is_separate(tmp_path: Path, change: str) -> None:
    args = control_inputs(tmp_path)
    if change == "source":
        (args["scan"] / "snapshot/exports/web.py").chmod(0o600)
        (args["scan"] / "snapshot/exports/web.py").write_text("changed\n")
    elif change == "plan":
        plan = json.loads(args["plan"].read_bytes())
        plan["findings"][0]["route"] = "<script>alert(1)</script>"
        args["plan"].write_text(json.dumps(plan))
    elif change == "missing_analysis":
        (args["investigation"] / "investigation.json").unlink()
    else:
        log = args["investigation"] / "diagnostics/version.log"
        if change == "missing_log":
            log.unlink()
        else:
            log.write_text("changed")
    report = write_repository_report(**inputs(args), validations=(), output=tmp_path / "report")
    assert report.integrity != "verified"
    html = (tmp_path / "report/report.html").read_text()
    assert "<script>" not in html
    if change == "plan":
        assert "&lt;script&gt;" in html


def test_changed_attempt_retains_recorded_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args, _ = setup(tmp_path, monkeypatch)
    args.pop("authorize_execution")
    validate_repository(**args, authorize_validation=True)
    path = args["output"] / "runtime/attempt.json"
    path.write_text("{}")
    report = write_repository_report(
        **inputs(args), validations=(args["output"],), output=tmp_path / "report"
    )
    assert report.integrity == "failed"
    assert report.validations[0].result
    assert report.validations[0].result.classification == "failed"
    assert report.validations[0].warnings


def test_unreadable_result_and_cli(tmp_path: Path) -> None:
    args = control_inputs(tmp_path)
    missing = tmp_path / "missing"
    command = ["report-repository"]
    for key, value in inputs(args).items():
        command.extend(["--" + key, str(value)])
    command.extend(["--validation", str(missing), "--output", str(tmp_path / "report")])
    assert main(command) == 1
    html = (tmp_path / "report/report.html").read_text()
    assert "Unassociated or unreadable" in html


def test_output_overlap_and_duplicate_selection(tmp_path: Path) -> None:
    args = control_inputs(tmp_path)
    with pytest.raises(ReportFailure, match="separate"):
        write_repository_report(**inputs(args), validations=(), output=args["scan"] / "report")
    with pytest.raises(ReportFailure, match="distinct"):
        write_repository_report(
            **inputs(args),
            validations=(tmp_path / "attempt", tmp_path / "attempt"),
            output=tmp_path / "report",
        )


@pytest.mark.parametrize("count", [0, 3])
def test_every_occurrence_including_duplicates_and_unknown_rules(
    tmp_path: Path, count: int
) -> None:
    from vulnproof.correlation.repository import correlate_repository, prepare_import
    from vulnproof.discovery.repository import discover
    from vulnproof.planning.repository import plan_repository
    from vulnproof.runner.repository import sha

    args = control_inputs(tmp_path)
    raw = json.loads((args["scan"] / "diagnostics/raw.sarif").read_bytes())
    original = raw["runs"][0]["results"][0]
    original["message"]["text"] = '<script>alert("scanner")</script>'
    raw["runs"][0]["results"] = (
        [original, original, {**original, "ruleId": "unknown"}] if count else []
    )
    scan = tmp_path / "second-scan"
    prepare_import(tmp_path / "checkout", None, json.dumps(raw).encode(), scan)
    args["scan"] = scan
    analysis = args["investigation"] / "investigation.json"
    record = json.loads(analysis.read_bytes())
    record["scan_sha256"] = sha((scan / "scan.json").read_bytes())
    analysis.write_text(json.dumps(record))
    args["correlation"].write_text(correlate_repository(scan, args["investigation"]))
    args["discovery"].write_text(discover(scan, args["investigation"], args["correlation"]))
    args["plan"].write_text(
        plan_repository(
            scan, args["investigation"], args["correlation"], args["discovery"], args["config"]
        )
    )
    report = write_repository_report(**inputs(args), validations=(), output=tmp_path / "report")
    assert report.integrity == "verified"
    assert len(report.plan["findings"]) == count
    assert len({r["finding_id"] for r in report.plan["findings"]}) == count
    html = (tmp_path / "report/report.html").read_text()
    assert "<script>" not in html
    if count:
        assert "unsupported_mapping" in html
        assert "&lt;script&gt;" in html


def test_reporting_never_starts_processes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    args = control_inputs(tmp_path, mode="import_failed")

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Reporting cannot start processes")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    report = write_repository_report(**inputs(args), validations=(), output=tmp_path / "report")
    from vulnproof.reporting.repository import RepositoryReport

    assert RepositoryReport.model_validate_json(report.model_dump_json()) == report


@pytest.mark.parametrize("mode", ["invalid", "symlink", "duplicate-key"])
def test_invalid_plan_does_not_publish(tmp_path: Path, mode: str) -> None:
    args = control_inputs(tmp_path)
    if mode == "symlink":
        original = tmp_path / "saved-plan.json"
        args["plan"].rename(original)
        args["plan"].symlink_to(original)
    else:
        args["plan"].write_text(
            '{"schema_version":"1.0","schema_version":"1.0"}' if mode == "duplicate-key" else "[]"
        )
    with pytest.raises(ReportFailure):
        write_repository_report(**inputs(args), validations=(), output=tmp_path / "report")
    assert not (tmp_path / "report").exists()
