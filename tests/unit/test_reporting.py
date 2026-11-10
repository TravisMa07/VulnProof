"""Reporting preserves semantics and treats retained files as untrusted data."""

import hashlib
import json
import os
from html.parser import HTMLParser
from pathlib import Path

import pytest
from scripts.export_report_schema import schema_text
from tests.report_support import ROOT, sample, save, with_attempt

from vulnproof.artifacts import read_local
from vulnproof.models import EvidenceBundle
from vulnproof.reporting import ReportDocument, ReportFailure, prepare_report, write_report
from vulnproof.reporting import prepare as preparation
from vulnproof.reporting.html import CSS, render_html


@pytest.mark.parametrize(
    "name",
    [
        "confirmed",
        "inconclusive",
        "unsupported",
        "failed",
        "unassessed",
        "no-path",
        "source-mismatch",
    ],
)
def test_every_evidence_example_is_preserved(tmp_path: Path, name: str) -> None:
    source = tmp_path / "validation"
    data = sample(source, name)
    result = prepare_report(source)
    assert result.evidence == EvidenceBundle.model_validate_json(json.dumps(data))
    assert (
        result.evidence.model_dump(mode="json", exclude_none=True)["finding"]["id"]
        == data["finding"]["id"]
    )
    assert json.loads(result.evidence.model_dump_json()) == json.loads(
        prepare_report(source).evidence.model_dump_json()
    )
    assert (
        result.evidence.assessment is None
        if name == "unassessed"
        else result.evidence.assessment is not None
    )
    if result.evidence.assessment is not None:
        assert result.evidence.assessment.classification == data["assessment"]["classification"]
    html = render_html(result)
    assert (
        "Recorded assessment: " + (data.get("assessment") or {}).get("classification", "unassessed")
        in html
    )
    assert "unsuccessful probe never establishes safety" in html
    assert result == prepare_report(source)


def test_complete_runtime_and_cleanup_failure_are_visible(tmp_path: Path) -> None:
    source = tmp_path / "validation"
    with_attempt(source, cleanup="unverified")
    result = write_report(source, tmp_path / "report")
    assert result.integrity == "verified"
    assert result.runtime[0].status == "available"
    assert (
        result.evidence.assessment is not None
        and result.evidence.assessment.classification == "failed"
    )
    html = (tmp_path / "report/report.html").read_text()
    for value in (
        "unverified",
        "observed",
        "Legitimate request control",
        "parent_traversal",
        "absolute_path",
        "Expected bytes SHA-256",
    ):
        assert value in html
    assert "selected" in html
    assert (
        ReportDocument.model_validate_json((tmp_path / "report/report.json").read_bytes()) == result
    )


@pytest.mark.parametrize(
    "change,expected,integrity",
    [
        ("missing", "missing", "incomplete"),
        ("changed", "changed", "failed"),
        ("truncated", "incomplete", "incomplete"),
        ("unknown", "incomplete", "incomplete"),
        ("size", "changed", "failed"),
    ],
)
def test_damaged_evidence_does_not_reclassify(
    tmp_path: Path, change: str, expected: str, integrity: str
) -> None:
    source = tmp_path / "validation"
    data = sample(source, "inconclusive" if change in ("unknown", "truncated") else "confirmed")
    ref = data["artifacts"][0]
    path = source / ref["path"]
    if change == "missing":
        path.unlink()
    elif change == "changed":
        path.write_text("tampered")
    elif change == "truncated":
        ref["truncated"] = True
    elif change == "unknown":
        ref["sha256"] = None
        ref["size_bytes"] = None
        ref["truncated"] = None
    elif change == "size":
        ref["size_bytes"] += 1
    save(source, data)
    result = prepare_report(source)
    assert result.artifacts[0].status == expected
    assert result.integrity == integrity
    assert (
        result.evidence.assessment is not None
        and result.evidence.assessment.classification == data["assessment"]["classification"]
    )
    assert "Retained artifact integrity: " + integrity in render_html(result)


@pytest.mark.parametrize("kind", ["symlink", "ancestor", "fifo"])
def test_unsafe_artifact_is_not_followed(tmp_path: Path, kind: str) -> None:
    source = tmp_path / "validation"
    data = sample(source)
    path = source / data["artifacts"][0]["path"]
    external = tmp_path / "secret"
    external.write_text("must-not-read")
    path.unlink()
    if kind == "symlink":
        path.symlink_to(external)
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.parent.rmdir()
        path.parent.symlink_to(tmp_path, target_is_directory=True)
    result = prepare_report(source)
    assert result.artifacts[0].status in ("unreadable", "missing")
    assert result.artifacts[0].preview == ""
    assert "must-not-read" not in result.model_dump_json()


def test_limits_and_previews_are_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "validation"
    with_attempt(source)
    monkeypatch.setattr(preparation, "MAX_PREVIEW_BYTES", 8)
    result = prepare_report(source)
    assert result.integrity == "verified"
    assert result.artifacts[0].preview_truncated
    assert result.artifacts[0].artifact.truncated is False
    monkeypatch.setattr(preparation, "MAX_ARTIFACT_BYTES", 8)
    limited = prepare_report(source)
    assert limited.artifacts[0].status == "limit_exceeded" and limited.integrity == "incomplete"
    assert limited.runtime[0].status == "unavailable"


def test_aggregate_budget_and_binary_preview(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "validation"
    data = sample(source)
    refs = data["artifacts"]
    first = refs[0]
    body = b"\x00\xffpayload"
    (source / first["path"]).write_bytes(body)
    first.update(sha256=hashlib.sha256(body).hexdigest(), size_bytes=len(body))
    second = dict(first, id="extra", path="extra.bin")
    refs.append(second)
    (source / second["path"]).write_bytes(body)
    save(source, data)
    monkeypatch.setattr(preparation, "MAX_TOTAL_BYTES", len(body))
    result = prepare_report(source)
    assert result.artifacts[0].preview_encoding == "base64"
    assert result.artifacts[1].status == "limit_exceeded"
    monkeypatch.setattr(preparation, "MAX_TOTAL_BYTES", 100)
    monkeypatch.setattr(preparation, "MAX_TOTAL_PREVIEW_BYTES", len(body))
    result = prepare_report(source)
    assert result.artifacts[1].preview_encoding == "none"
    assert result.artifacts[1].preview_truncated
    assert result.integrity == "verified"


class Markup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


def test_hostile_content_is_passive_text(tmp_path: Path) -> None:
    source = tmp_path / "validation"
    data = sample(source)
    attack = '</pre><script>alert(1)</script><img src="https://evil.invalid/x" onerror="alert(2)">'
    data["finding"]["rule_id"] = attack + "\u202e"
    data["assessment"]["reasons"][0]["message"] = attack
    ref = data["artifacts"][0]
    payload = attack.encode()
    (source / ref["path"]).write_bytes(payload)
    ref.update(sha256=hashlib.sha256(payload).hexdigest(), size_bytes=len(payload))
    save(source, data)
    rendered = render_html(prepare_report(source))
    parser = Markup()
    parser.feed(rendered)
    assert not any(
        tag in ("script", "img", "iframe", "object", "embed", "a", "link", "form")
        for tag, _ in parser.tags
    )
    assert not any(name.startswith("on") for _, attrs in parser.tags for name in attrs)
    assert "&lt;script&gt;" in rendered and "\\u202e" in rendered
    assert "Content-Security-Policy" in rendered
    assert "sha256-" in rendered and CSS in rendered


def test_result_bounds_and_schema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "validation"
    sample(source)
    assert (ROOT / "schemas/report-v1.schema.json").read_text() == schema_text()
    monkeypatch.setattr(preparation, "MAX_RESULT_BYTES", 8)
    with pytest.raises(ReportFailure):
        prepare_report(source)


def test_changed_result_during_inspection_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "validation"
    sample(source)
    original = read_local
    calls = 0

    def changing(root: Path, path: str, limit: int) -> bytes:
        nonlocal calls
        data = original(root, path, limit)
        if path == "result.json":
            calls += 1
            if calls == 2:
                return data + b" "
        return data

    monkeypatch.setattr(preparation, "read_local", changing)
    with pytest.raises(ReportFailure, match="changed"):
        prepare_report(source)
