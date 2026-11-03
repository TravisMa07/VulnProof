"""Validate records and their relationships, without scanners, Docker, or file hashing."""

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from scripts.export_evidence_schema import schema_text

from vulnproof.models import EvidenceBundle, SourceLocation

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "docs/examples/evidence"


def example(name: str = "confirmed") -> dict[str, Any]:
    data: dict[str, Any] = json.loads((EXAMPLES / f"{name}.json").read_text())
    return data


def validate(data: dict[str, Any]) -> EvidenceBundle:
    return EvidenceBundle.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "name",
    [
        "confirmed",
        "inconclusive",
        "unsupported",
        "failed",
        "source-mismatch",
        "no-path",
        "unassessed",
    ],
)
def test_documented_examples_round_trip(name: str) -> None:
    bundle = validate(example(name))
    assert EvidenceBundle.model_validate_json(bundle.model_dump_json()) == bundle
    assert EvidenceBundle.model_validate(bundle.model_dump()) == bundle


def test_schema_matches_models() -> None:
    assert (ROOT / "schemas/evidence-bundle-v1.schema.json").read_text() == schema_text()
    schema = json.loads(schema_text())
    assert schema["properties"]["schema_version"]["const"] == "1.0"
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize("version", ["2.0", 1, None])
def test_unknown_version_rejected(version: object) -> None:
    data = example()
    data["schema_version"] = version
    with pytest.raises(ValidationError):
        validate(data)


def test_version_must_be_explicit() -> None:
    data = example()
    del data["schema_version"]
    with pytest.raises(ValidationError, match="schema_version"):
        validate(data)


@pytest.mark.parametrize(
    "path,value,message",
    [
        (("finding", "location", "start_line"), "19", "valid integer"),
        (("finding", "location", "start_line"), True, "valid integer"),
        (("finding", "location", "start_line"), 0, "greater than 0"),
        (("finding", "location", "end_line"), 1, "precedes"),
        (("finding", "location", "path"), "../app.py", "relative POSIX path"),
        (("finding", "location", "path"), "/tmp/app.py", "relative POSIX path"),
        (("finding", "location", "path"), "file:///tmp/app.py", "relative POSIX path"),
        (("finding", "location", "path"), "a/./app.py", "relative POSIX path"),
        (("finding", "location", "path"), "C:\\app.py", "relative POSIX path"),
        (("snapshots", 0, "fingerprint"), "bad-hash", "pattern"),
        (("snapshots", 0, "commit_id"), "short-sha", "pattern"),
        (("assessment", "classification"), "safe", "Input should be"),
        (("assessment", "reasons"), [], "at least 1"),
        (("assessment", "execution_evidence_id"), "unknown", "unknown execution"),
        (("assessment", "static_evidence_id"), "unknown", "unknown static"),
        (("assessment", "static_path_id"), "unknown", "different static evidence"),
        (("execution_evidence", 0, "finding_id"), "another-finding", "different finding"),
        (("execution_evidence", 0, "artifact_ids"), ["unknown"], "unknown artifact"),
        (("execution_evidence", 0, "static_path_id"), "unknown", "unknown static evidence/path"),
        (("execution_evidence", 0, "static_evidence_id"), None, "supplied together"),
        (("execution_evidence", 0, "oracle"), "not_observed", "positive oracle"),
        (("execution_evidence", 0, "oracle_id"), None, "oracle identifier"),
        (("execution_evidence", 0, "image_id"), None, "immutable image ID"),
        (("execution_evidence", 0, "source", "state"), "unverified", "matched provenance"),
        (("static_evidence", 0, "outcome"), "no_path_found", "other outcomes"),
        (("static_evidence", 0, "paths"), [], "path_found requires"),
        (("static_evidence", 0, "cwe"), "CWE-78", "shared declared CWE"),
        (("static_evidence", 0, "paths", 0, "locations", 1, "path"), "other.py", "overlap"),
        (("static_evidence", 0, "paths", 0, "locations", 1, "start_line"), 50, "overlap"),
        (("artifacts", 0, "id"), "static-1", "identifiers must be unique"),
        (("artifacts", 0, "sha256"), None, "complete, hashed"),
        (("artifacts", 0, "truncated"), True, "complete, hashed"),
        (("artifacts", 0, "truncated"), None, "complete, hashed"),
        (("artifacts", 0, "size_bytes"), -1, "greater than or equal to 0"),
    ],
)
def test_rejects_inconsistent_confirmation(
    path: tuple[str | int, ...],
    value: object,
    message: str,
) -> None:
    data = example()
    cursor = data
    for key in path[:-1]:
        cursor = cursor[key]  # type: ignore[index]
    cursor[path[-1]] = value  # type: ignore[index]
    with pytest.raises(ValidationError, match=message):
        validate(data)


@pytest.mark.parametrize("nested", [False, True])
def test_unknown_fields_rejected(nested: bool) -> None:
    data = example()
    destination = data["finding"]["scanner"] if nested else data
    destination["unexpected"] = "not discarded"
    with pytest.raises(ValidationError, match="Extra inputs"):
        validate(data)


def test_commit_alone_cannot_establish_match() -> None:
    data = example()
    data["snapshots"][0]["fingerprint"] = None
    assert data["snapshots"][0]["commit_id"]
    with pytest.raises(ValidationError, match="content fingerprints"):
        validate(data)


def test_dirty_content_under_same_commit_is_distinct() -> None:
    data = example("source-mismatch")
    assert data["snapshots"][0]["commit_id"] == data["snapshots"][1]["commit_id"]
    assert validate(data).execution_evidence[0].source.state == "mismatched"
    data["execution_evidence"][0]["source"]["state"] = "matched"
    with pytest.raises(ValidationError, match="contradicts"):
        validate(data)


def test_equal_fingerprints_cannot_be_declared_mismatched() -> None:
    data = example("inconclusive")
    data["execution_evidence"][0]["source"]["state"] = "mismatched"
    with pytest.raises(ValidationError, match="contradicts"):
        validate(data)


@pytest.mark.parametrize("reference", ["expected_snapshot_id", "observed_snapshot_id"])
def test_snapshot_references_must_resolve(reference: str) -> None:
    data = example()
    data["finding"]["source"][reference] = "missing-snapshot"
    with pytest.raises(ValidationError, match="snapshot"):
        validate(data)


def test_matched_binding_requires_observed_snapshot() -> None:
    data = example()
    data["finding"]["source"]["observed_snapshot_id"] = None
    with pytest.raises(ValidationError, match="observed snapshot"):
        validate(data)


def test_equal_hashes_do_not_automatically_elevate_unverified_binding() -> None:
    data = example("inconclusive")
    data["finding"]["source"]["state"] = "unverified"
    result = validate(data)
    assert result.finding.source.state == "unverified"
    assert result.assessment is not None
    assert result.assessment.classification == "inconclusive"


def test_conflicting_file_hashes_rejected_for_matched_snapshots() -> None:
    data = example()
    observed = deepcopy(data["snapshots"][0])
    observed["id"] = "snapshot-observed"
    observed["files"][0]["sha256"] = "2" * 64
    data["snapshots"].append(observed)
    data["execution_evidence"][0]["source"]["observed_snapshot_id"] = observed["id"]
    with pytest.raises(ValidationError, match="conflicting file hashes"):
        validate(data)


def test_duplicate_file_paths_rejected() -> None:
    data = example()
    data["snapshots"][0]["files"].append(deepcopy(data["snapshots"][0]["files"][0]))
    with pytest.raises(ValidationError, match="duplicate file paths"):
        validate(data)


def test_not_run_cannot_claim_an_observation() -> None:
    data = example("inconclusive")
    data["execution_evidence"][0]["outcome"] = "not_run"
    with pytest.raises(ValidationError, match="did not run"):
        validate(data)


def test_failed_execution_may_retain_partial_observation_but_cannot_confirm() -> None:
    data = example("failed")
    data["execution_evidence"][0].update(
        oracle="observed",
        oracle_id="cwe22-canary",
        image_id="sha256:" + "e" * 64,
        reasons=[
            {"code": "timeout_after_observation", "message": "Evidence arrived before timeout."}
        ],
    )
    result = validate(data)
    assert result.execution_evidence[0].oracle == "observed"
    data["assessment"]["classification"] = "confirmed"
    with pytest.raises(ValidationError, match="completed execution"):
        validate(data)


def test_all_attempts_retained_with_explicit_selected_support() -> None:
    data = example()
    other = deepcopy(data["execution_evidence"][0])
    other.update(id="execution-2", oracle="not_observed")
    data["execution_evidence"].append(other)
    result = validate(data)
    assert len(result.execution_evidence) == 2
    assert result.assessment is not None
    assert result.assessment.execution_evidence_id == "execution-1"


def test_selected_path_must_be_the_executed_path() -> None:
    data = example()
    other = deepcopy(data["static_evidence"][0]["paths"][0])
    other["id"] = "path-2"
    data["static_evidence"][0]["paths"].append(other)
    data["assessment"]["static_path_id"] = "path-2"
    with pytest.raises(ValidationError, match="path targeted by the execution"):
        validate(data)


def test_frozen_records_prevent_accidental_in_place_changes() -> None:
    result = validate(example())
    with pytest.raises(ValidationError, match="frozen"):
        result.finding.source.state = "unverified"  # type: ignore[misc]
    assert isinstance(result.execution_evidence, tuple)


def test_validation_does_not_read_or_verify_artifacts(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps(example())

    def deny(*args: object, **kwargs: object) -> None:
        raise AssertionError("record validation must not read files")

    monkeypatch.setattr(Path, "open", deny)
    result = EvidenceBundle.model_validate_json(payload)
    assert result.assessment is not None
    assert result.assessment.classification == "confirmed"


def test_unassessed_evidence_does_not_invent_a_classification() -> None:
    data = example()
    del data["assessment"]
    assert validate(data).assessment is None


def test_disjoint_columns_do_not_overlap() -> None:
    left = SourceLocation(path="app.py", start_line=1, start_column=1, end_column=5)
    right = SourceLocation(path="app.py", start_line=1, start_column=5, end_column=9)
    assert not left.overlaps(right)
    with pytest.raises(ValidationError, match="end_column"):
        SourceLocation(path="app.py", start_line=1, start_column=10, end_column=5)
