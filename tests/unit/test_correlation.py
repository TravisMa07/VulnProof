"""Synthetic scanner/analysis observations; no scanner, extractor, or fixture executes."""

import hashlib
import importlib
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from tests.static_pipeline import codeql_sarif, prepare, scanner_sarif

from vulnproof.cli import main
from vulnproof.correlation import CorrelationDocument, CorrelationFailure, correlate


def test_single_candidate_preserves_observations_and_provenance(tmp_path: Path) -> None:
    capture, analysis = prepare(tmp_path)
    report = correlate(capture, analysis)
    finding = report.findings[0]
    assert finding.status == "single_candidate"
    assert finding.imported.finding.source.state == finding.scanner_source_state == "unverified"
    assert finding.imported.finding.original_ref == "#/runs/0/results/0"
    assert finding.candidates[0].paths[0].original_ref.endswith("/codeFlows/0/threadFlows/0")
    assert (
        report.analysis_sha256
        == hashlib.sha256((analysis / "analysis.json").read_bytes()).hexdigest()
    )
    assert CorrelationDocument.model_validate_json(report.model_dump_json()) == report
    assert correlate(capture, analysis).model_dump_json() == report.model_dump_json()
    assert "assessment" not in report.model_dump()


@pytest.mark.parametrize(
    "results,alternatives,status",
    [
        (1, 2, "single_candidate"),
        (2, 1, "ambiguous"),
        (0, 1, "no_candidate"),
    ],
)
def test_result_groups_and_alternatives(
    tmp_path: Path, results: int, alternatives: int, status: str
) -> None:
    report = correlate(
        *prepare(tmp_path, raw=codeql_sarif(results=results, alternatives=alternatives))
    )
    assert report.findings[0].status == status
    assert len(report.findings[0].candidates) == results
    if results:
        assert len(report.findings[0].candidates[0].paths) == alternatives


@pytest.mark.parametrize(
    "kwargs,status",
    [
        ({"rule": "another.rule"}, "unsupported_mapping"),
        ({"cwe": "CWE-78"}, "unsupported_mapping"),
        ({"line": 18}, "no_candidate"),
        ({"uri": "other.py"}, "location_unavailable"),
        ({"line": 100}, "location_unavailable"),
        ({"start_column": 30, "end_column": 35}, "no_candidate"),
        ({"start_column": 20, "end_column": 25}, "single_candidate"),
    ],
)
def test_compatibility_and_regions(tmp_path: Path, kwargs: dict[str, Any], status: str) -> None:
    capture, analysis = prepare(
        tmp_path, scanner_sarif(**kwargs), codeql_sarif(start_column=19, end_column=23)
    )
    assert correlate(capture, analysis).findings[0].status == status


def test_duplicates_remain_distinct_and_can_share_a_path(tmp_path: Path) -> None:
    report = correlate(*prepare(tmp_path, scanner_sarif(duplicates=2)))
    left, right = report.findings
    assert left.imported.finding.id != right.imported.finding.id
    assert right.imported.duplicate_of == left.imported.finding.id
    assert left.candidates == right.candidates


def test_partial_analysis_retains_complete_candidate(tmp_path: Path) -> None:
    report = correlate(*prepare(tmp_path, raw=codeql_sarif(partial=True)))
    assert report.analysis_normalization == "partial"
    assert report.findings[0].status == "single_candidate"
    assert "analysis_partial" in {r.code for r in report.findings[0].reasons}
    assert report.findings[0].candidates[0].diagnostics


def test_failed_analysis_is_an_observation_not_input_failure(tmp_path: Path) -> None:
    report = correlate(*prepare(tmp_path, failed=True))
    assert report.findings[0].status == "analysis_failed"
    assert not report.findings[0].candidates


@pytest.mark.parametrize(
    "path", ["diagnostics/raw.sarif", "diagnostics/query.log", "work/source/app.py"]
)
def test_modified_artifacts_rejected(tmp_path: Path, path: str) -> None:
    capture, analysis = prepare(tmp_path)
    target = analysis / path
    target.chmod(0o644)
    target.write_bytes(b"modified")
    with pytest.raises(CorrelationFailure):
        correlate(capture, analysis)


def test_normalized_record_edit_rejected_even_if_valid_json(tmp_path: Path) -> None:
    capture, analysis = prepare(tmp_path)
    path = analysis / "analysis.json"
    data = json.loads(path.read_bytes())
    data["results"][0]["id"] = "invented-result"
    path.write_text(json.dumps(data))
    with pytest.raises(CorrelationFailure):
        correlate(capture, analysis)


def test_snapshot_mismatch_rejected(tmp_path: Path) -> None:
    capture, analysis = prepare(tmp_path)
    path = analysis / "analysis.json"
    data = json.loads(path.read_bytes())
    data["snapshot"]["fingerprint"] = "f" * 64
    path.write_text(json.dumps(data))
    with pytest.raises(CorrelationFailure, match="selected capture"):
        correlate(capture, analysis)


@pytest.mark.parametrize("kind", ["file", "directory", "root", "fifo"])
def test_unsafe_artifact_paths_rejected(tmp_path: Path, kind: str) -> None:
    capture, analysis = prepare(tmp_path)
    if kind == "root":
        link = tmp_path / "linked-analysis"
        link.symlink_to(analysis, target_is_directory=True)
        analysis = link
    elif kind == "directory":
        (analysis / "diagnostics").rename(analysis / "real-diagnostics")
        (analysis / "diagnostics").symlink_to(
            analysis / "real-diagnostics", target_is_directory=True
        )
    else:
        target = analysis / "diagnostics/query.log"
        target.unlink()
        if kind == "file":
            target.symlink_to(analysis / "diagnostics/version.log")
        else:
            import os

            os.mkfifo(target)
    with pytest.raises(CorrelationFailure):
        correlate(capture, analysis)


def test_cli_publication_and_no_overwrite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capture, analysis = prepare(tmp_path)
    output = tmp_path / "correlation.json"
    args = [
        "correlate",
        "--capture",
        str(capture),
        "--analysis",
        str(analysis),
        "--output",
        str(output),
    ]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["candidate_results"] == 1
    before = output.read_bytes()
    assert main(args) == 2
    assert output.read_bytes() == before
    assert main(args[:-1] + [str(analysis / "inside.json")]) == 2
    assert not (analysis / "inside.json").exists()


def test_model_rejects_contradictory_candidate_status(tmp_path: Path) -> None:
    data = correlate(*prepare(tmp_path)).model_dump(mode="json")
    data["findings"][0]["status"] = "no_candidate"
    with pytest.raises(ValidationError):
        CorrelationDocument.model_validate_json(json.dumps(data))


@pytest.mark.parametrize("limit", ["MAX_CANDIDATES", "MAX_CANDIDATE_LOCATIONS"])
def test_candidate_limits_fail_without_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: str
) -> None:
    capture, analysis = prepare(tmp_path)
    engine = importlib.import_module("vulnproof.correlation.engine")
    monkeypatch.setattr(engine, limit, 0)
    with pytest.raises(CorrelationFailure, match="bounded limits"):
        correlate(capture, analysis)


def test_artifact_byte_limit_is_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    capture, analysis = prepare(tmp_path)
    engine = importlib.import_module("vulnproof.correlation.engine")
    monkeypatch.setattr(engine, "MAX_LOG_BYTES", 1)
    with pytest.raises(CorrelationFailure):
        correlate(capture, analysis)


@pytest.mark.parametrize("path", ["../outside", "/outside"])
def test_declared_artifact_escape_is_rejected(tmp_path: Path, path: str) -> None:
    capture, analysis = prepare(tmp_path)
    target = analysis / "analysis.json"
    data = json.loads(target.read_bytes())
    data["raw_sarif"]["path"] = path
    target.write_text(json.dumps(data))
    with pytest.raises(CorrelationFailure):
        correlate(capture, analysis)


def test_unusable_paths_are_not_promoted_to_candidates(tmp_path: Path) -> None:
    report = correlate(*prepare(tmp_path, raw=codeql_sarif(alternatives=0, partial=True)))
    assert report.analysis_normalization == "partial"
    assert report.findings[0].status == "no_candidate"
    assert not report.findings[0].candidates


def test_unknown_mapping_retains_global_analysis_failure(tmp_path: Path) -> None:
    report = correlate(*prepare(tmp_path, scanner_sarif(rule="unknown"), failed=True))
    assert report.findings[0].status == "unsupported_mapping"
    assert report.analysis_outcome == "failed"
    assert report.diagnostics[0].code == "synthetic_failure"


def test_failed_report_without_artifacts_is_supported(tmp_path: Path) -> None:
    capture, analysis = prepare(tmp_path, failed=True)
    target = analysis / "analysis.json"
    data = json.loads(target.read_bytes())
    data["commands"] = []
    data["raw_sarif"] = None
    target.write_text(json.dumps(data))
    report = correlate(capture, analysis)
    assert report.raw_sarif_sha256 is None
    assert report.findings[0].status == "analysis_failed"


def test_no_findings_is_valid(tmp_path: Path) -> None:
    report = correlate(*prepare(tmp_path, b'{"version":"2.1.0","runs":[]}'))
    assert report.findings == ()


def test_missing_inputs_fail_cli_without_publication(tmp_path: Path) -> None:
    target = tmp_path / "never-created.json"
    assert (
        main(
            [
                "correlate",
                "--capture",
                str(tmp_path / "absent"),
                "--analysis",
                str(tmp_path / "also-absent"),
                "--output",
                str(target),
            ]
        )
        == 2
    )
    assert not target.exists()
