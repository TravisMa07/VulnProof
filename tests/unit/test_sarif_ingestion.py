"""Observable ingestion behavior and hostile-input boundaries, without scanners."""

import copy
import hashlib
import json
from typing import Any

import pytest
from pydantic import ValidationError

from vulnproof.ingest import ImportFailure, IngestionDocument, ingest_sarif
from vulnproof.ingest.sarif import MAX_INPUT_BYTES


@pytest.fixture
def sarif() -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep OSS",
                        "semanticVersion": "1.122.0",
                        "rules": [
                            {
                                "id": "example.traversal",
                                "properties": {
                                    "tags": ["security", "CWE-22: Path Traversal", "CWE-78"]
                                },
                            }
                        ],
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": [
                    {
                        "ruleId": "example.traversal",
                        "message": {"text": "Untrusted <input>"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py", "uriBaseId": "%SRCROOT%"},
                                    "region": {"startLine": 18, "startColumn": 5, "endColumn": 20},
                                }
                            }
                        ],
                        "level": "warning",
                        "fingerprints": {"scanner-id": "scanner-declared"},
                    }
                ],
            }
        ],
    }


def encode(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, ensure_ascii=False).encode()


def test_roundtrip_and_exact_original_preservation(sarif: dict[str, Any]) -> None:
    raw = b" \n" + encode(sarif) + b"\n"
    doc = ingest_sarif(raw)
    finding = doc.findings[0].finding
    assert doc.raw_sarif.encode() == raw
    assert doc.input_sha256 == hashlib.sha256(raw).hexdigest()
    assert doc.input_size_bytes == len(raw)
    assert doc.status == "complete"
    assert doc.result_count == 1
    assert finding.cwes == ("CWE-22", "CWE-78")
    assert finding.location.path == "app.py"
    assert finding.location.start_line == 18
    assert finding.original_ref == "#/runs/0/results/0"
    assert finding.source.state == "unverified"
    assert finding.source.observed_snapshot_id is None
    assert doc.snapshots[0].fingerprint is None
    assert doc.snapshots[0].commit_id is None
    assert IngestionDocument.model_validate_json(doc.model_dump_json()) == doc
    assert ingest_sarif(raw).model_dump_json() == doc.model_dump_json()
    assert "assessment" not in doc.model_dump()


def test_all_results_accounted_for_and_runs_isolated(sarif: dict[str, Any]) -> None:
    run = sarif["runs"][0]
    run["results"] += [{"ruleId": "broken"}, copy.deepcopy(run["results"][0])]
    sarif["runs"].append(copy.deepcopy(run))
    doc = ingest_sarif(encode(sarif))
    assert doc.status == "partial"
    assert doc.result_count == 6
    assert len(doc.findings) == 4
    assert [(r.imported_count, r.rejected_count) for r in doc.runs] == [(2, 1), (2, 1)]
    assert doc.findings[1].duplicate_of == doc.findings[0].finding.id
    assert doc.findings[2].duplicate_of is None
    assert len({f.finding.id for f in doc.findings}) == 4
    assert doc.snapshots[0].id != doc.snapshots[1].id
    assert {d.pointer for d in doc.diagnostics if d.code == "invalid_result"} == {
        "/runs/0/results/1",
        "/runs/1/results/1",
    }


@pytest.mark.parametrize(
    "uri",
    [
        "../secret",
        "/etc/passwd",
        "file:///etc/passwd",
        "https://example.org/a.py",
        "C:/app.py",
        "app\\file.py",
        "%2e%2e/secret",
        "%252e%252e/secret",
        "app.py?",
        "app.py#",
        "app%00.py",
        "app%0a.py",
        "app%xy.py",
        "app%ff.py",
        "./app.py",
        "a//b.py",
        "//host/share",
        "a/../b.py",
    ],
)
def test_unsafe_or_unsupported_locations_rejected(sarif: dict[str, Any], uri: str) -> None:
    sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = uri
    doc = ingest_sarif(encode(sarif))
    assert doc.status == "partial"
    assert not doc.findings
    assert doc.runs[0].rejected_count == 1


def test_percent_encoded_relative_uri_is_decoded_once(sarif: dict[str, Any]) -> None:
    artifact = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]
    artifact["uri"] = "src/my%20file.py"
    doc = ingest_sarif(encode(sarif))
    assert doc.findings[0].finding.location.path == "src/my file.py"


@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b"[]",
        b"\xff",
        b'{"version":"2.1.0","version":"2.1.0","runs":[]}',
        b'{"version":"2.1.0","runs":[],"x":NaN}',
        b'{"version":"2.1.0","runs":[],"x":1e999}',
        b'{"version":"2.1.0","runs":[],"x":"\\ud800"}',
        b"[" * 65 + b"0" + b"]" * 65,
    ],
)
def test_ambiguous_or_malformed_json_rejected(raw: bytes) -> None:
    with pytest.raises(ImportFailure, match="UTF-8 JSON"):
        ingest_sarif(raw)


@pytest.mark.parametrize(
    "doc", [{}, {"version": "2.2", "runs": []}, {"version": "2.1.0", "runs": {}}]
)
def test_unsupported_top_level_rejected(doc: dict[str, Any]) -> None:
    with pytest.raises(ImportFailure) as exc:
        ingest_sarif(encode(doc))
    assert exc.value.code == "unsupported_document"


def test_size_limit() -> None:
    with pytest.raises(ImportFailure) as exc:
        ingest_sarif(b" " * (MAX_INPUT_BYTES + 1))
    assert exc.value.code == "input_too_large"


def test_result_limit(sarif: dict[str, Any]) -> None:
    sarif["runs"][0]["results"] = [{}] * 10_001
    with pytest.raises(ImportFailure) as exc:
        ingest_sarif(encode(sarif))
    assert exc.value.code == "too_many_results"


@pytest.mark.parametrize(
    "edit",
    [
        {"ruleIndex": True},
        {"ruleIndex": -1},
        {"ruleIndex": 99},
        {"ruleIndex": 0, "ruleId": "different"},
        {"rule": {"toolComponent": {"index": 0}}},
        {"locations": []},
        {"locations": None},
        {"message": {}},
        {"level": "critical"},
        {"suppressions": "invalid"},
    ],
)
def test_invalid_result_fields(sarif: dict[str, Any], edit: dict[str, Any]) -> None:
    sarif["runs"][0]["results"][0].update(edit)
    doc = ingest_sarif(encode(sarif))
    assert not doc.findings
    assert doc.status == "partial"


@pytest.mark.parametrize(
    "edit",
    [
        {"startLine": 0},
        {"startLine": True},
        {"startLine": "18"},
        {"endLine": 17},
        {"endColumn": 2},
    ],
)
def test_invalid_regions(sarif: dict[str, Any], edit: dict[str, Any]) -> None:
    sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"].update(edit)
    assert not ingest_sarif(encode(sarif)).findings


def test_rule_index_and_unknown_rule(sarif: dict[str, Any]) -> None:
    result = sarif["runs"][0]["results"][0]
    del result["ruleId"]
    result["ruleIndex"] = 0
    assert ingest_sarif(encode(sarif)).findings[0].finding.rule_id == "example.traversal"
    del result["ruleIndex"]
    result["ruleId"] = "unfamiliar.rule.CWE-999"
    doc = ingest_sarif(encode(sarif))
    assert doc.findings[0].finding.cwes == ()
    assert doc.status == "complete"


def test_suppression_additional_locations_and_missing_version(sarif: dict[str, Any]) -> None:
    del sarif["runs"][0]["tool"]["driver"]["semanticVersion"]
    result = sarif["runs"][0]["results"][0]
    result["suppressions"] = [{"kind": "inSource", "status": "accepted"}]
    result["locations"].append({"logicalLocations": [{"name": "helper"}]})
    doc = ingest_sarif(encode(sarif))
    assert doc.findings[0].suppression == "present"
    assert doc.findings[0].finding.scanner.version is None
    assert {d.code for d in doc.diagnostics} == {"suppressed_result", "additional_locations"}


@pytest.mark.parametrize(
    "invocations, status",
    [
        ([], "unknown"),
        ([{"executionSuccessful": False}], "reported_problems"),
        (
            [{"executionSuccessful": True, "toolExecutionNotifications": [{"level": "warning"}]}],
            "reported_problems",
        ),
        ([{"executionSuccessful": "true"}], "unknown"),
    ],
)
def test_scan_status_preserved(
    sarif: dict[str, Any], invocations: list[object], status: str
) -> None:
    sarif["runs"][0]["invocations"] = invocations
    doc = ingest_sarif(encode(sarif))
    assert doc.runs[0].scan_status == status
    assert len(doc.findings) == 1
    assert doc.diagnostics


@pytest.mark.parametrize("run", [None, {"results": []}, {"tool": {}, "results": "bad"}])
def test_unusable_run_retained_as_diagnostic(sarif: dict[str, Any], run: object) -> None:
    sarif["runs"].append(run)
    doc = ingest_sarif(encode(sarif))
    assert doc.status == "partial"
    assert doc.runs[1].supported is False
    assert len(doc.findings) == 1


def test_foreign_scanner_and_external_properties(sarif: dict[str, Any]) -> None:
    run = sarif["runs"][0]
    run["tool"]["driver"]["name"] = "CodeQL"
    assert ingest_sarif(encode(sarif)).runs[0].rejected_count == 1
    run["tool"]["driver"]["name"] = "Semgrep"
    run["externalPropertyFileReferences"] = {
        "results": [{"location": {"uri": "https://example.org"}}]
    }
    assert not ingest_sarif(encode(sarif)).findings


def test_empty_report() -> None:
    doc = ingest_sarif(b'{"version":"2.1.0","runs":[]}')
    assert doc.status == "complete"
    assert doc.result_count == 0
    assert not doc.findings


@pytest.mark.parametrize(
    "field, value",
    [
        ("status", "partial"),
        ("result_count", 99),
        ("input_sha256", "a" * 64),
        ("input_size_bytes", 1),
        ("schema_version", "2.0"),
    ],
)
def test_ingestion_contract_rejects_inconsistent_documents(
    sarif: dict[str, Any], field: str, value: object
) -> None:
    document = json.loads(ingest_sarif(encode(sarif)).model_dump_json())
    document[field] = value
    with pytest.raises(ValidationError):
        IngestionDocument.model_validate_json(json.dumps(document))


@pytest.mark.parametrize("mutation", ["snapshot", "duplicate", "position", "count", "run"])
def test_ingestion_reference_and_count_integrity(sarif: dict[str, Any], mutation: str) -> None:
    document = json.loads(ingest_sarif(encode(sarif)).model_dump_json())
    item = document["findings"][0]
    if mutation == "snapshot":
        item["finding"]["source"]["expected_snapshot_id"] = "missing"
    elif mutation == "duplicate":
        item["duplicate_of"] = "missing"
    elif mutation == "position":
        item["result_index"] = 999
    elif mutation == "count":
        document["runs"][0]["imported_count"] = 0
    else:
        item["run_index"] = 2
    with pytest.raises(ValidationError):
        IngestionDocument.model_validate_json(json.dumps(document))


def test_run_and_rule_limits(sarif: dict[str, Any]) -> None:
    many_runs = {"version": "2.1.0", "runs": [{}] * 129}
    with pytest.raises(ImportFailure) as exc:
        ingest_sarif(encode(many_runs))
    assert exc.value.code == "too_many_runs"
    sarif["runs"][0]["tool"]["driver"]["rules"] = [{}] * 10_001
    doc = ingest_sarif(encode(sarif))
    assert doc.runs[0].rejected_count == 1


def test_inconsistent_rule_descriptors_and_other_bases(sarif: dict[str, Any]) -> None:
    run = sarif["runs"][0]
    run["tool"]["driver"]["rules"].append(copy.deepcopy(run["tool"]["driver"]["rules"][0]))
    assert not ingest_sarif(encode(sarif)).findings
    run["tool"]["driver"]["rules"].pop()
    artifact = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    artifact["uriBaseId"] = "OTHER"
    assert not ingest_sarif(encode(sarif)).findings
    artifact["uriBaseId"] = "%SRCROOT%"
    artifact["index"] = 0
    assert not ingest_sarif(encode(sarif)).findings


def test_crlf_and_unicode_are_preserved(sarif: dict[str, Any]) -> None:
    sarif["runs"][0]["results"][0]["message"]["text"] = "Unicode: café 日本語"
    raw = json.dumps(sarif, ensure_ascii=False, indent=2).replace("\n", "\r\n").encode()
    assert ingest_sarif(raw).raw_sarif.encode() == raw


def test_importer_never_reads_paths_or_contacts_network(
    sarif: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    import builtins
    import socket

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Importer attempted IO")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    assert ingest_sarif(encode(sarif)).findings
