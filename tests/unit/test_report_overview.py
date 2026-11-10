"""Readable diagrams must remain faithful to the selected path and verified records."""

import hashlib
from pathlib import Path

from tests.report_support import ROOT, sample, save, with_attempt

from vulnproof.reporting import prepare_report
from vulnproof.reporting.html import render_html
from vulnproof.reporting.overview import render_overview


def illustrated_source(root: Path) -> dict[str, object]:
    data = with_attempt(root)
    source = (ROOT / "fixtures/cwe22/vulnerable/app.py").read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    data["snapshots"][0]["files"][0]["sha256"] = digest
    ref = dict(
        id="illustrative:source",
        path="evidence/source/app.py",
        media_type="text/plain",
        sha256=digest,
        size_bytes=len(source),
        truncated=False,
    )
    data["artifacts"].append(ref)
    path = root / "evidence/source/app.py"
    path.parent.mkdir(parents=True)
    path.write_bytes(source)
    data["static_evidence"][0]["paths"][0]["locations"] = [
        dict(path="app.py", start_line=line) for line in (6, 6, 14, 14, 17, 19)
    ]
    save(root, data)
    return data


def test_flow_groups_locations_without_changing_evidence(tmp_path: Path) -> None:
    root = tmp_path / "validation"
    illustrated_source(root)
    report = prepare_report(root)
    original = report.evidence.model_dump_json()
    html = render_overview(report)
    for expected in (
        "Modeled data flow",
        "Recorded runtime checks",
        "Read the request parameter",
        "Build the file path",
        "Read the file",
        "request.args.get",
        "os.path.join",
        "2 modeled locations grouped",
        "Parent-directory traversal",
        "name=../../tmp/vulnproof/[fresh-file].txt",
        "exact canary contents returned",
        "not a runtime trace",
        "reconstructed probe inputs",
    ):
        assert expected in html
    assert report.evidence.model_dump_json() == original
    assert len(report.evidence.static_evidence[0].paths[0].locations) == 6
    full = render_html(report)
    assert full.index("Modeled data flow") < full.index("Inspect technical evidence")
    assert '<details class="technical"><summary>' in full


def test_changed_source_cannot_supply_a_code_excerpt(tmp_path: Path) -> None:
    root = tmp_path / "validation"
    illustrated_source(root)
    (root / "evidence/source/app.py").write_text("attacker-controlled source")
    report = prepare_report(root)
    html = render_overview(report)
    assert "Source excerpt unavailable" in html
    assert "os.path.join" not in html and "attacker-controlled" not in html
    assert report.integrity == "failed"


def test_no_selected_path_is_not_implicitly_chosen(tmp_path: Path) -> None:
    root = tmp_path / "validation"
    data = sample(root)
    data["assessment"] = None
    save(root, data)
    html = render_overview(prepare_report(root))
    assert "No static path is selected" in html
    assert "Flask request model" not in html
    assert "stored assessment alone" in html


def test_positive_disclosure_with_cleanup_failure_is_not_promoted(tmp_path: Path) -> None:
    root = tmp_path / "validation"
    with_attempt(root, cleanup="unverified")
    html = render_overview(prepare_report(root))
    assert "Disclosure was observed, but this finding is not confirmed" in html
    assert "Container absence not verified" in html


def test_missing_attempt_does_not_get_an_observed_exploit_story(tmp_path: Path) -> None:
    root = tmp_path / "validation"
    data = with_attempt(root)
    (root / data["artifacts"][0]["path"]).unlink()
    html = render_overview(prepare_report(root))
    assert "application returned the exact contents" not in html
    assert "Runtime details are unavailable" in html


def test_long_paths_have_explicit_omission_marker(tmp_path: Path) -> None:
    root = tmp_path / "validation"
    data = with_attempt(root)
    data["static_evidence"][0]["paths"][0]["locations"] = [
        dict(path="app.py", start_line=line) for line in list(range(1, 30)) + [19]
    ]
    save(root, data)
    report = prepare_report(root)
    assert "grouped steps omitted from this overview" in render_overview(report)
    assert len(report.evidence.static_evidence[0].paths[0].locations) == 30


def test_negative_probes_remain_inconclusive(tmp_path: Path) -> None:
    import json

    root = tmp_path / "validation"
    data = with_attempt(root)
    ref = data["artifacts"][0]
    attempt_path = root / ref["path"]
    attempt = json.loads(attempt_path.read_bytes())
    for probe in attempt["driver"]["probes"]:
        probe.update(status=404, body_base64="bm90IGZvdW5k")
    body = json.dumps(attempt).encode()
    attempt_path.write_bytes(body)
    ref.update(sha256=hashlib.sha256(body).hexdigest(), size_bytes=len(body))
    data["execution_evidence"][0]["oracle"] = "not_observed"
    data["assessment"]["classification"] = "inconclusive"
    data["assessment"]["reasons"] = [
        dict(code="not_disclosed", message="Bounded probes did not disclose the canary")
    ]
    save(root, data)
    html = render_overview(prepare_report(root))
    assert "do not establish that the application is safe" in html
    assert "no exact canary disclosure" in html
    assert "demonstrates file access beyond" not in html


def test_partial_attempt_does_not_draw_an_unexecuted_probe(tmp_path: Path) -> None:
    import json

    root = tmp_path / "validation"
    data = with_attempt(root)
    ref = data["artifacts"][0]
    path = root / ref["path"]
    attempt = json.loads(path.read_bytes())
    attempt["driver"].update(
        outcome="failed", probes=attempt["driver"]["probes"][:1], errors=["later_failure"]
    )
    attempt.update(
        execution="failed", reasons=[dict(code="driver_failed", message="Later driver failure")]
    )
    body = json.dumps(attempt).encode()
    path.write_bytes(body)
    ref.update(sha256=hashlib.sha256(body).hexdigest(), size_bytes=len(body))
    data["execution_evidence"][0].update(
        outcome="failed", reasons=[dict(code="driver_failed", message="Later driver failure")]
    )
    data["assessment"]["classification"] = "failed"
    save(root, data)
    html = render_overview(prepare_report(root))
    assert "Parent-directory traversal" in html
    assert "Absolute-path probe" not in html and "Absolute-path input" not in html
    assert "Disclosure was observed, but this finding is not confirmed" in html
