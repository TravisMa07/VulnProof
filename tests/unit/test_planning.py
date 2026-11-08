"""Plan construction never starts tools, imports fixtures, or authorizes execution."""

import hashlib
import importlib
import json
import os
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pydantic import ValidationError
from tests.static_pipeline import ROOT, codeql_sarif, prepare, scanner_sarif

from vulnproof.cli import main
from vulnproof.correlation import correlate
from vulnproof.planning import PlanningDocument, PlanningFailure, create_plans, planning_catalog


def inputs(
    tmp_path: Path, *, scanner: bytes | None = None, raw: bytes | None = None, failed: bool = False
) -> tuple[Path, Path, Path]:
    capture, analysis = prepare(tmp_path, scanner, raw, failed=failed)
    correlation = tmp_path / "correlation.json"
    correlation.write_text(correlate(capture, analysis).model_dump_json(indent=2) + "\n")
    return capture, analysis, correlation


def test_draft_is_reviewable_and_preserves_unmet_prerequisites(tmp_path: Path) -> None:
    capture, analysis, correlation = inputs(tmp_path)
    report = create_plans(capture, analysis, correlation)
    entry = report.findings[0]
    assert entry.disposition == "draft"
    assert entry.plan is not None
    assert entry.plan.execution_authorized is False
    assert entry.plan.scanner_source_state == "unverified"
    assert {r.code for r in entry.plan.unmet_prerequisites} == {
        "scanner_source_unverified",
        "execution_authorization_required",
        "approved_image_required",
        "runtime_oracle_required",
    }
    assert report.fixture.route == "/download"
    assert report.fixture.input_name == "name"
    assert report.fixture.method == "GET"
    assert [s.kind for s in report.template.steps] == [
        "legitimate_request",
        "prepare_canary",
        "parent_traversal",
        "absolute_path",
    ]
    assert report.template.steps[0].exact_body == "legitimate_document"
    assert report.template.steps[1].fresh_nonce_bytes == 32
    assert report.template.steps[2].exact_body == "fresh_canary"
    assert report.template.unsuccessful_probe == "no_safety_conclusion"
    assert report.correlation_sha256 == hashlib.sha256(correlation.read_bytes()).hexdigest()
    assert PlanningDocument.model_validate_json(report.model_dump_json()) == report
    assert (
        create_plans(capture, analysis, correlation).model_dump_json() == report.model_dump_json()
    )
    assert "classification" not in report.model_dump_json()


@pytest.mark.parametrize(
    "raw,scanner,failed,code",
    [
        (codeql_sarif(results=2), None, False, "ambiguous"),
        (codeql_sarif(partial=True), None, False, "analysis_partial"),
        (codeql_sarif(results=0), None, False, "no_candidate"),
        (None, scanner_sarif(rule="unknown.rule"), False, "unsupported_mapping"),
        (None, scanner_sarif(uri="absent.py"), False, "location_unavailable"),
        (None, None, True, "analysis_failed"),
    ],
)
def test_blocked_inputs_remain_distinct(
    tmp_path: Path, raw: bytes | None, scanner: bytes | None, failed: bool, code: str
) -> None:
    report = create_plans(*inputs(tmp_path, scanner=scanner, raw=raw, failed=failed))
    entry = report.findings[0]
    assert entry.disposition == "blocked"
    assert entry.plan is None
    assert entry.reasons[0].code == code
    assert report.correlation.findings[0].imported.finding.source.state == "unverified"


def test_alternatives_are_one_plan_with_all_path_references(tmp_path: Path) -> None:
    report = create_plans(*inputs(tmp_path, raw=codeql_sarif(alternatives=2)))
    assert len(report.findings) == 1
    plan = report.findings[0].plan
    assert plan is not None
    assert plan.path_ids == tuple(
        p.path.id for p in report.correlation.findings[0].candidates[0].paths
    )
    assert len(plan.path_ids) == 2


def test_duplicate_occurrences_are_retained(tmp_path: Path) -> None:
    report = create_plans(*inputs(tmp_path, scanner=scanner_sarif(duplicates=2)))
    left, right = report.findings
    assert left.finding_id != right.finding_id
    assert left.plan is not None and right.plan is not None
    assert left.plan.candidate_result_id == right.plan.candidate_result_id
    assert report.correlation.findings[1].imported.duplicate_of == left.finding_id


def test_zero_findings_is_valid(tmp_path: Path) -> None:
    report = create_plans(*inputs(tmp_path, scanner=b'{"version":"2.1.0","runs":[]}'))
    assert report.findings == ()


@pytest.mark.parametrize("edit", ["remove", "change_id", "policy", "source_state"])
def test_edited_correlation_cannot_select_tests(tmp_path: Path, edit: str) -> None:
    capture, analysis, correlation = inputs(tmp_path)
    data = json.loads(correlation.read_bytes())
    if edit == "remove":
        data["findings"] = []
    elif edit == "change_id":
        data["findings"][0]["candidates"][0]["id"] = "invented"
    elif edit == "policy":
        data["policy"]["rule_sha256"] = "a" * 64
    else:
        data["findings"][0]["scanner_source_state"] = "matched"
    correlation.write_text(json.dumps(data))
    with pytest.raises(PlanningFailure):
        create_plans(capture, analysis, correlation)


def test_whitespace_changes_are_allowed_and_exact_bytes_are_hashed(tmp_path: Path) -> None:
    capture, analysis, correlation = inputs(tmp_path)
    correlation.write_text(json.dumps(json.loads(correlation.read_bytes()), separators=(",", ":")))
    assert (
        create_plans(capture, analysis, correlation).correlation_sha256
        == hashlib.sha256(correlation.read_bytes()).hexdigest()
    )


@pytest.mark.parametrize("kind", ["symlink", "ancestor", "fifo", "oversized", "malformed"])
def test_correlation_input_boundaries(
    tmp_path: Path, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture, analysis, correlation = inputs(tmp_path)
    if kind == "symlink":
        link = tmp_path / "linked.json"
        link.symlink_to(correlation)
        correlation = link
    elif kind == "ancestor":
        directory = tmp_path / "linked"
        directory.symlink_to(tmp_path, target_is_directory=True)
        correlation = directory / correlation.name
    elif kind == "fifo":
        correlation.unlink()
        os.mkfifo(correlation)
    elif kind == "oversized":
        monkeypatch.setattr(
            importlib.import_module("vulnproof.planning.engine"), "MAX_DOCUMENT_BYTES", 1
        )
    else:
        correlation.write_bytes(b"{malformed")
    with pytest.raises(PlanningFailure):
        create_plans(capture, analysis, correlation)


def test_modified_analysis_is_not_hidden_by_correlation(tmp_path: Path) -> None:
    capture, analysis, correlation = inputs(tmp_path)
    (analysis / "diagnostics/raw.sarif").write_bytes(b"modified")
    with pytest.raises(PlanningFailure):
        create_plans(capture, analysis, correlation)


def test_untrusted_metadata_cannot_supply_execution_configuration(tmp_path: Path) -> None:
    raw = json.loads(scanner_sarif())
    result = raw["runs"][0]["results"][0]
    result["message"]["text"] = "--privileged http://outside.invalid/ ; command"
    result["properties"] = {
        "template": "arbitrary",
        "image": "untrusted:latest",
        "route": "http://outside.invalid/",
        "mount": "/:/host",
    }
    report = create_plans(*inputs(tmp_path, scanner=json.dumps(raw).encode()))
    assert report.fixture.route == "/download"
    assert report.execution_requirements.host_mounts is False
    assert report.execution_requirements.network == "none"
    assert report.template.id == "cwe22-file-read-v1"
    assert "outside.invalid" not in report.template.model_dump_json()
    assert "outside.invalid" not in report.fixture.model_dump_json()


def test_planning_does_not_start_processes_or_import_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = inputs(tmp_path)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Execution attempted during planning")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("vulnproof.static.analyze_capture", forbidden)
    original_import = importlib.import_module

    def checked_import(name: str, package: str | None = None) -> ModuleType:
        if name == "app" or name.startswith("fixtures"):
            raise AssertionError("Fixture import attempted during planning")
        return original_import(name, package)

    monkeypatch.setattr("importlib.import_module", checked_import)
    assert create_plans(*args).findings[0].disposition == "draft"


def test_catalog_binding_document_matches_real_fixture_data() -> None:
    catalog = planning_catalog()
    expected = hashlib.sha256(
        (ROOT / "fixtures/cwe22/data/downloads/example.txt").read_bytes()
    ).hexdigest()
    assert all(b.legitimate_document_sha256 == expected for b in catalog.bindings)


def test_patched_fixture_uses_its_own_identity_without_a_forced_plan(tmp_path: Path) -> None:
    capture, analysis = prepare(
        tmp_path, b'{"version":"2.1.0","runs":[]}', codeql_sarif(results=0), variant="patched"
    )
    correlation = tmp_path / "patched-correlation.json"
    correlation.write_text(correlate(capture, analysis).model_dump_json())
    report = create_plans(capture, analysis, correlation)
    assert report.fixture.fixture_id == "cwe22-patched-v1"
    assert report.findings == ()


def test_serialized_output_limit_fails_without_publishing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = inputs(tmp_path)
    report_size = len(args[2].read_bytes())
    # Admit the input but reject the larger document containing the draft and catalog.
    monkeypatch.setattr(
        importlib.import_module("vulnproof.planning.engine"), "MAX_DOCUMENT_BYTES", report_size
    )
    with pytest.raises(PlanningFailure, match="output exceeds"):
        create_plans(*args)


@pytest.mark.parametrize(
    "edit", ["authorize", "path", "candidate", "prerequisite", "omit", "endpoint", "image"]
)
def test_model_rejects_inconsistent_or_executable_plans(tmp_path: Path, edit: str) -> None:
    data: dict[str, Any] = create_plans(*inputs(tmp_path)).model_dump(mode="json")
    plan = data["findings"][0]["plan"]
    if edit == "authorize":
        plan["execution_authorized"] = True
    elif edit == "path":
        plan["path_ids"] = ["foreign-path"]
    elif edit == "candidate":
        plan["candidate_result_id"] = "foreign-result"
    elif edit == "prerequisite":
        plan["unmet_prerequisites"] = plan["unmet_prerequisites"][:1]
    elif edit == "omit":
        data["findings"] = []
    elif edit == "endpoint":
        data["fixture"]["route"] = "http://outside.invalid/"
    else:
        plan["image"] = "untrusted:latest"
    with pytest.raises(ValidationError):
        PlanningDocument.model_validate_json(json.dumps(data))


def test_cli_publication_and_no_overwrite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capture, analysis, correlation = inputs(tmp_path)
    output = tmp_path / "plans.json"
    args = [
        "plan",
        "--capture",
        str(capture),
        "--analysis",
        str(analysis),
        "--correlation",
        str(correlation),
        "--output",
        str(output),
    ]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out) == {
        "status": "completed",
        "drafts": 1,
        "blocked": 0,
        "execution_authorized": False,
    }
    before = output.read_bytes()
    assert main(args) == 2
    assert output.read_bytes() == before
    for invalid in (analysis / "inside.json", capture / "inside.json", correlation):
        assert main(args[:-1] + [str(invalid)]) == 2


def test_cli_blocked_is_successful_planning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capture, analysis, correlation = inputs(tmp_path, raw=codeql_sarif(results=2))
    assert (
        main(
            [
                "plan",
                "--capture",
                str(capture),
                "--analysis",
                str(analysis),
                "--correlation",
                str(correlation),
                "--output",
                str(tmp_path / "blocked.json"),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["blocked"] == 1


def test_invalid_input_does_not_publish(tmp_path: Path) -> None:
    output = tmp_path / "never.json"
    assert (
        main(
            [
                "plan",
                "--capture",
                str(tmp_path / "absent"),
                "--analysis",
                str(tmp_path / "absent"),
                "--correlation",
                str(tmp_path / "absent.json"),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert not output.exists()
