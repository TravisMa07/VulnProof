"""The end-to-end diagram must expose evidence gaps instead of drawing success."""

from pathlib import Path

from tests.report_support import sample, save, with_attempt

from vulnproof.reporting import prepare_report
from vulnproof.reporting.pipeline import render_pipeline


def test_complete_chain_keeps_stage_order_and_evidence(tmp_path: Path) -> None:
    root = tmp_path / "validation"
    with_attempt(root)
    report = prepare_report(root)
    original = report.evidence.model_dump_json()
    rendered = render_pipeline(report)
    titles = [
        "Scanner finding &amp; normalization",
        "Bind exact source and revision",
        "Analyze modeled reachability",
        "Correlate finding, path, and plan",
        "Authorize the approved fixture",
        "Run the restricted Docker test",
        "Observe controls, probes, cleanup",
        "Correlate evidence and classify",
    ]
    positions = [rendered.index(title) for title in titles]
    assert positions == sorted(positions)
    assert "Semgrep" in rendered and "CodeQL" in rendered
    assert "Explicit validation authorization is recorded" in rendered
    assert "container absence verified" in rendered
    assert "Recorded assessment: confirmed" in rendered
    assert "Retained plan artifact: not supplied" in rendered
    assert "does not imply native analysis tools ran inside Docker" in rendered
    assert report.evidence.model_dump_json() == original


def test_missing_attempt_does_not_imply_container_execution(tmp_path: Path) -> None:
    root = tmp_path / "validation"
    data = with_attempt(root)
    (root / data["artifacts"][0]["path"]).unlink()
    rendered = render_pipeline(prepare_report(root))
    assert "This report does not assume a container ran" in rendered
    assert "Missing records do not imply authorization" in rendered
    assert "Explicit validation authorization is recorded" not in rendered
    assert "Bundle oracle: observed" in rendered
    assert "Retained artifact integrity: incomplete" in rendered


def test_disclosure_followed_by_cleanup_failure_stays_failed(tmp_path: Path) -> None:
    root = tmp_path / "validation"
    with_attempt(root, cleanup="unverified")
    rendered = render_pipeline(prepare_report(root))
    assert "Exact fresh-canary disclosure: observed" in rendered
    assert "container absence NOT verified" in rendered
    assert "Recorded assessment: failed" in rendered
    assert "needs-attention" in rendered


def test_unverified_scanner_provenance_is_visible(tmp_path: Path) -> None:
    root = tmp_path / "validation"
    data = with_attempt(root)
    for record in [data["finding"], *data["static_evidence"], *data["execution_evidence"]]:
        record["source"]["state"] = "unverified"
    data["assessment"]["classification"] = "inconclusive"
    save(root, data)
    rendered = render_pipeline(prepare_report(root))
    assert "Unverified: scanner-to-source relationship is not established" in rendered
    assert "Exact fresh-canary disclosure: observed" in rendered
    assert "Recorded assessment: inconclusive" in rendered


def test_unassessed_record_does_not_choose_an_analysis_or_execution(tmp_path: Path) -> None:
    root = tmp_path / "validation"
    data = sample(root)
    data["assessment"] = None
    save(root, data)
    rendered = render_pipeline(prepare_report(root))
    assert "No static evidence selected" in rendered
    assert "none; no path chosen by this report" in rendered
    assert "Bundle execution: none selected" in rendered
    assert "Recorded assessment: unassessed" in rendered


def test_untrusted_scanner_fields_remain_text(tmp_path: Path) -> None:
    root = tmp_path / "validation"
    data = with_attempt(root)
    data["finding"]["scanner"]["version"] = "</li><script>alert(1)</script>"
    save(root, data)
    rendered = render_pipeline(prepare_report(root))
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
