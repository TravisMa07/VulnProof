"""Fake-tool failure tests; actual Semgrep acceptance runs separately."""

import json
import shutil
import sys
import time
from pathlib import Path

import pytest
from tests.static_pipeline import ROOT, scanner_sarif

from vulnproof.cli import main
from vulnproof.ingest import IngestionDocument
from vulnproof.scanning import ScanFailure, scan_fixture, scan_profile, verify_scan
from vulnproof.scanning.models import ScanCommand, ToolPreparation
from vulnproof.scanning.process import command


def setup_scan(tmp_path: Path, *, duplicates: int = 1, mode: str = "ok") -> tuple[Path, Path, Path]:
    source = tmp_path / "source"
    shutil.copytree(ROOT / "fixtures/cwe22/vulnerable", source)
    environment = tmp_path / "tool"
    (environment / "bin").mkdir(parents=True)
    marker = ToolPreparation(
        schema_version="1.0",
        profile="fixture-semgrep-v1",
        version="1.184.0",
        python="3.14",
        uv="0.13.6",
        lock_sha256=scan_profile().lock_sha256,
    )
    (environment / "prepared.json").write_text(marker.model_dump_json())
    raw = json.loads(scanner_sarif(duplicates=duplicates))
    raw["runs"][0]["tool"]["driver"]["version"] = "1.184.0"
    if mode == "unsupported":
        raw["runs"][0]["results"][0]["ruleId"] = "unexpected-rule"
    if mode == "location":
        raw["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] = (
            9999
        )
    executable = environment / "bin/semgrep"
    executable.write_text(f"""#!{sys.executable}
import os, sys
from pathlib import Path
if "--version" in sys.argv:
    print("0.0.0" if {mode!r} == "wrong" else "1.184.0")
else:
    assert os.environ.get("SEMGREP_SEND_METRICS") == "off"
    assert "GITHUB_TOKEN" not in os.environ
    assert "--oss-only" in sys.argv and "--no-rewrite-rule-ids" in sys.argv
    assert sys.argv[-1] == "app.py"
    if {mode!r} == "fail": sys.exit(7)
    if {mode!r} == "mutate":
        p = Path("app.py"); p.chmod(0o600); p.write_text("changed")
    Path(sys.argv[sys.argv.index("--output") + 1]).write_text({json.dumps(raw)!r})
""")
    executable.chmod(0o700)
    return source, tmp_path / "scan", environment


def test_association_preserves_original(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-reach-tool")
    source, output, tool = setup_scan(tmp_path, duplicates=2)
    receipt = scan_fixture(source, output, tool)
    assert receipt.outcome == "completed"
    result = verify_scan(output)
    assert result == verify_scan(output)
    assert len(result.findings) == 2
    assert len({f.bound.id for f in result.findings}) == 2
    for finding in result.findings:
        assert finding.original.source.state == "unverified"
        assert finding.bound.source.state == "matched"
        assert finding.original.model_dump(exclude={"source"}) == finding.bound.model_dump(
            exclude={"source"}
        )
    ingestion = IngestionDocument.model_validate_json((output / "ingestion.json").read_bytes())
    assert all(f.finding.source.state == "unverified" for f in ingestion.findings)
    assert result.snapshot == receipt.snapshot


def test_zero_findings_is_only_observation(tmp_path: Path) -> None:
    source, output, tool = setup_scan(tmp_path, duplicates=0)
    assert scan_fixture(source, output, tool).outcome == "completed"
    assert verify_scan(output).findings == ()


@pytest.mark.parametrize(
    "mode,reason",
    [
        ("wrong", "scanner_version"),
        ("fail", "scanner_failed"),
        ("mutate", "source_or_policy_changed"),
        ("unsupported", "invalid_scan_report"),
        ("location", "capture_mismatch"),
    ],
)
def test_failed_scan_cannot_bind(tmp_path: Path, mode: str, reason: str) -> None:
    source, output, tool = setup_scan(tmp_path, mode=mode)
    receipt = scan_fixture(source, output, tool)
    assert receipt.outcome == "failed"
    assert receipt.snapshot is None
    assert receipt.reasons[0].code == reason
    with pytest.raises(ScanFailure):
        verify_scan(output)


@pytest.mark.parametrize(
    "target",
    [
        "diagnostics/raw.sarif",
        "diagnostics/scan.stdout",
        "ingestion.json",
        "tool-preparation.json",
        "capture/snapshot/provenance.json",
        "capture/snapshot/source/app.py",
        "work/source/app.py",
        "work/rule.yaml",
        "scan.json",
    ],
)
def test_tampering_rejected(tmp_path: Path, target: str) -> None:
    source, output, tool = setup_scan(tmp_path)
    scan_fixture(source, output, tool)
    path = output / target
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b" ")
    if target == "scan.json":
        document = json.loads(path.read_bytes())
        document["profile_sha256"] = "0" * 64
        path.write_text(json.dumps(document))
    with pytest.raises(ScanFailure):
        verify_scan(output)


def test_unapproved_source_and_missing_tool(tmp_path: Path) -> None:
    source, output, tool = setup_scan(tmp_path)
    (source / "extra.py").write_text("unapproved")
    with pytest.raises(ScanFailure):
        scan_fixture(source, output, tool)
    assert not output.exists()
    (source / "extra.py").unlink()
    (tool / "prepared.json").unlink()
    with pytest.raises(ScanFailure):
        scan_fixture(source, output, tool)


def test_symlink_artifact_rejected(tmp_path: Path) -> None:
    source, output, tool = setup_scan(tmp_path)
    scan_fixture(source, output, tool)
    path = output / "diagnostics/raw.sarif"
    replacement = tmp_path / "copy.sarif"
    replacement.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(replacement)
    with pytest.raises(ScanFailure):
        verify_scan(output)


def test_stale_tool_lock_rejected_before_execution(tmp_path: Path) -> None:
    source, output, tool = setup_scan(tmp_path)
    path = tool / "prepared.json"
    marker = json.loads(path.read_bytes())
    marker["lock_sha256"] = "0" * 64
    path.write_text(json.dumps(marker))
    with pytest.raises(ScanFailure, match="lock identity"):
        scan_fixture(source, output, tool)
    assert not output.exists()


def test_interruption_retains_failed_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, output, tool = setup_scan(tmp_path)
    original_sleep = time.sleep
    interrupted = False

    def interrupt(seconds: float) -> None:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt
        original_sleep(seconds)

    monkeypatch.setattr(time, "sleep", interrupt)
    with pytest.raises(KeyboardInterrupt):
        scan_fixture(source, output, tool)
    receipt = json.loads((output / "scan.json").read_bytes())
    assert receipt["outcome"] == "failed"
    assert receipt["commands"][0]["outcome"] == "interrupted"
    with pytest.raises(ScanFailure):
        verify_scan(output)


def test_cli_publication(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source, output, tool = setup_scan(tmp_path)
    assert (
        main(
            [
                "scan-fixture",
                "--source-root",
                str(source),
                "--output",
                str(output),
                "--semgrep-environment",
                str(tool),
            ]
        )
        == 0
    )
    derived = tmp_path / "verified.json"
    args = ["verify-scan", "--scan", str(output), "--output", str(derived)]
    assert main(args) == 0
    assert main(args) == 2
    assert main(["verify-scan", "--scan", str(output), "--output", str(output / "new.json")]) == 2
    assert "source_associated" in capsys.readouterr().out


@pytest.mark.parametrize(
    "script,timeout,outcome",
    [
        ("import time; time.sleep(10)", 0.05, "timed_out"),
        ("print('x' * 1100000)", 3, "output_limit"),
        ("raise SystemExit(3)", 3, "failed"),
    ],
)
def test_process_failure_limits(tmp_path: Path, script: str, timeout: float, outcome: str) -> None:
    (tmp_path / "diagnostics").mkdir()
    (tmp_path / "work/source").mkdir(parents=True)
    records: list[ScanCommand] = []
    with pytest.raises(ScanFailure):
        command(
            [sys.executable, "-c", script],
            stage="scan",
            root=tmp_path,
            env={},
            records=records,
            timeout=timeout,
        )
    assert records[0].outcome == outcome
    assert sum((a.size_bytes or 0) for a in (records[0].stdout, records[0].stderr)) <= 1024 * 1024
