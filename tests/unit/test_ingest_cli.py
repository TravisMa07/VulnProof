"""File boundaries, exit status, and actual module entry point."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vulnproof.cli import _publish, main
from vulnproof.ingest import IngestionDocument


def write_input(tmp_path: Path, *, partial: bool = False) -> Path:
    path = tmp_path / "input.sarif"
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Semgrep"}},
                        "invocations": [{"executionSuccessful": True}],
                        "results": [{}] if partial else [],
                    }
                ],
            }
        )
    )
    return path


@pytest.mark.parametrize("partial, expected", [(False, 0), (True, 1)])
def test_cli_publishes_complete_or_partial_document(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], partial: bool, expected: int
) -> None:
    source = write_input(tmp_path, partial=partial)
    output = tmp_path / "output.json"
    assert main(["ingest", "--sarif", str(source), "--output", str(output)]) == expected
    doc = IngestionDocument.model_validate_json(output.read_text())
    assert doc.raw_sarif == source.read_text()
    assert (output.stat().st_mode & 0o777) == 0o600
    assert list(tmp_path.glob(".vulnproof-*")) == []
    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == doc.status
    if partial:
        assert "invalid_result" in captured.err


def test_existing_output_and_input_are_never_overwritten(tmp_path: Path) -> None:
    source = write_input(tmp_path)
    before = source.read_bytes()
    assert main(["ingest", "--sarif", str(source), "--output", str(source)]) == 2
    assert source.read_bytes() == before
    output = tmp_path / "output.json"
    output.write_text("owner content")
    assert main(["ingest", "--sarif", str(source), "--output", str(output)]) == 2
    assert output.read_text() == "owner content"
    assert not list(tmp_path.glob(".vulnproof-*"))


def test_output_symlink_is_not_followed(tmp_path: Path) -> None:
    source = write_input(tmp_path)
    output = tmp_path / "link.json"
    output.symlink_to(tmp_path / "absent")
    assert main(["ingest", "--sarif", str(source), "--output", str(output)]) == 2
    assert not (tmp_path / "absent").exists()
    assert output.is_symlink()


@pytest.mark.parametrize("kind", ["missing", "directory", "fifo", "invalid_json"])
def test_bad_input_publishes_no_output(tmp_path: Path, kind: str) -> None:
    source = tmp_path / "input"
    if kind == "directory":
        source.mkdir()
    elif kind == "fifo":
        os.mkfifo(source)
    elif kind == "invalid_json":
        source.write_text("{broken")
    output = tmp_path / "output.json"
    assert main(["ingest", "--sarif", str(source), "--output", str(output)]) == 2
    assert not output.exists()


def test_failed_publication_cleans_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_link(source: str, target: Path) -> None:
        raise OSError("simulated publication failure")

    monkeypatch.setattr(os, "link", fail_link)
    with pytest.raises(OSError):
        _publish(tmp_path / "output.json", "complete content")
    assert list(tmp_path.iterdir()) == []


def test_interrupted_write_publishes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupt(descriptor: int) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "fsync", interrupt)
    with pytest.raises(KeyboardInterrupt):
        _publish(tmp_path / "output.json", "complete content")
    assert list(tmp_path.iterdir()) == []


def test_module_entrypoint_from_another_directory(tmp_path: Path) -> None:
    source = write_input(tmp_path)
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "vulnproof",
            "ingest",
            "--sarif",
            str(source),
            "--output",
            str(tmp_path / "output.json"),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["status"] == "complete"


def test_usage_errors() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["ingest"])
    assert exc.value.code == 2
