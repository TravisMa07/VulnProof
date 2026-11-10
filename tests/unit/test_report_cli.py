"""Offline CLI behavior, exclusive publication, and malformed input rejection."""

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from tests.report_support import sample, save, with_attempt

from vulnproof.cli import main
from vulnproof.reporting import ReportFailure, engine, prepare, write_report


def test_cli_is_offline_and_preserves_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "validation"
    with_attempt(source)
    before = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob("*") if p.is_file()}

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("reporting must not execute tools")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    output = tmp_path / "report"
    assert main(["report", "--validation", str(source), "--output", str(output)]) == 0
    message = json.loads(capsys.readouterr().out)
    assert message["recorded_assessment"] == "confirmed"
    assert message["artifact_integrity"] == "verified"
    assert sorted(p.name for p in output.iterdir()) == ["report.html", "report.json"]
    assert (output.stat().st_mode & 0o777) == 0o700
    after = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    assert before == after
    first = (output / "report.json").read_bytes()
    assert main(["report", "--validation", str(source), "--output", str(output)]) == 2
    assert (output / "report.json").read_bytes() == first


def test_integrity_warning_writes_both_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "validation"
    data = with_attempt(source)
    (source / data["artifacts"][0]["path"]).unlink()
    output = tmp_path / "report"
    assert main(["report", "--validation", str(source), "--output", str(output)]) == 1
    message = json.loads(capsys.readouterr().out)
    assert message["recorded_assessment"] == "confirmed"
    assert message["artifact_integrity"] == "incomplete"
    assert (output / "report.html").exists()


@pytest.mark.parametrize(
    "mode", ["malformed", "version", "graph", "result-symlink", "root-symlink", "count"]
)
def test_bad_input_creates_no_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    source = tmp_path / "validation"
    data = sample(source)
    if mode == "malformed":
        (source / "result.json").write_text("broken JSON")
    elif mode == "version":
        data["schema_version"] = "99.0"
        (source / "result.json").write_text(json.dumps(data))
    elif mode == "graph":
        data["assessment"]["static_path_id"] = "absent-path"
        (source / "result.json").write_text(json.dumps(data))
    elif mode == "result-symlink":
        path = source / "result.json"
        copy = tmp_path / "external.json"
        copy.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(copy)
    elif mode == "root-symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(source, target_is_directory=True)
        source = alias
    else:
        monkeypatch.setattr(prepare, "MAX_ARTIFACTS", 0)
    output = tmp_path / "report"
    assert main(["report", "--validation", str(source), "--output", str(output)]) == 2
    assert not output.exists()


def test_output_must_be_outside_evidence(tmp_path: Path) -> None:
    source = tmp_path / "validation"
    sample(source)
    with pytest.raises(ReportFailure, match="outside"):
        write_report(source, source / "report")
    alias = tmp_path / "alias"
    alias.symlink_to(source, target_is_directory=True)
    with pytest.raises(ReportFailure):
        write_report(source, alias / "report")


def test_oversized_render_has_no_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "validation"
    sample(source)
    monkeypatch.setattr(engine, "MAX_OUTPUT_BYTES", 1)
    with pytest.raises(ReportFailure, match="64 MiB"):
        write_report(source, tmp_path / "report")
    assert not (tmp_path / "report").exists()


def test_second_file_failure_cleans_only_created_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "validation"
    sample(source)
    original = os.open
    output = tmp_path / "report"

    def fail(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if path == "report.html" and flags & os.O_EXCL:
            raise OSError("authored write failure")
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", fail)
    with pytest.raises(ReportFailure):
        write_report(source, output)
    assert not output.exists()


def test_invalid_attempt_remains_visible_as_warning(tmp_path: Path) -> None:
    import hashlib

    source = tmp_path / "validation"
    data = with_attempt(source)
    ref = data["artifacts"][0]
    attempt_path = source / ref["path"]
    attempt = json.loads(attempt_path.read_bytes())
    attempt["finding_id"] = "different-finding"
    body = json.dumps(attempt).encode()
    attempt_path.write_bytes(body)
    ref.update(sha256=hashlib.sha256(body).hexdigest(), size_bytes=len(body))
    save(source, data)
    document = write_report(source, tmp_path / "report")
    assert document.integrity == "verified"
    assert document.runtime[0].status == "invalid"
    assert (
        document.evidence.assessment is not None
        and document.evidence.assessment.classification == "confirmed"
    )
    assert any(r.code == "runtime_detail_invalid" for r in document.warnings)
