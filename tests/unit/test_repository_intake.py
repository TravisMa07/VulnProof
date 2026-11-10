"""Cross-producer occurrence accounting and safe on-demand source observations."""

import json
import os
from pathlib import Path
from typing import Any

import pytest

from vulnproof.cli import main
from vulnproof.intake import inventory


def finding(ref: dict[str, Any], line: int = 1) -> dict[str, Any]:
    return {
        "ruleId": "unmapped",
        "message": {"text": "scanner observation"},
        "locations": [
            {"physicalLocation": {"artifactLocation": ref, "region": {"startLine": line}}}
        ],
    }


def run(results: object) -> dict[str, Any]:
    return {"tool": {"driver": {"name": "Unregistered scanner"}}, "results": results}


def sarif(*runs: object) -> bytes:
    return json.dumps({"version": "2.1.0", "runs": runs}).encode()


def test_mixed_runs_all_occurrences_and_revisions(tmp_path: Path) -> None:
    (tmp_path / "README").write_bytes(b"one\rtwo")
    first = finding({"index": 0}, 2)
    r = run([first, first, None, finding({"uri": "gone"}), finding({"uri": "README"}, 3)])
    r["artifacts"] = [{"location": {"uri": "README", "uriBaseId": "%SRCROOT%"}}]
    r["versionControlProvenance"] = [{"revisionId": "scanner-claim"}]
    raw = sarif(r, run({}), run([]))
    inv = inventory(raw, tmp_path)
    rows = inv.runs[0].entries
    assert inv.raw_sarif.encode() == raw and inv.result_count == len(rows) == 5
    assert rows[0].locations[0].state == "present" and rows[0].rule_id == "unmapped"
    assert rows[1].duplicate_of == rows[0].id and rows[1].id != rows[0].id
    assert rows[2].issues == ["invalid_result"]
    assert rows[3].locations[0].state == "missing_file"
    assert rows[4].locations[0].state == "line_out_of_range"
    assert inv.runs[1].result_count is None and inv.runs[2].result_count == 0
    assert inv.scanner_source_state == "unverified" and inv.runs[0].declared_revisions == [
        "scanner-claim"
    ]
    assert inv.status == "partial"


@pytest.mark.parametrize(
    "uri", ["../secret", "%2e%2e/secret", "file:///tmp/private", "https://host/source", "/abs/path"]
)
def test_unsafe_locations_retained(tmp_path: Path, uri: str) -> None:
    row = inventory(sarif(run([finding({"uri": uri})])), tmp_path).runs[0].entries[0]
    assert row.locations[0].state == "unsupported_or_unsafe_uri"


def test_symlinks_special_paths_conflicts_and_filter(tmp_path: Path) -> None:
    (tmp_path / "alias").symlink_to(tmp_path / "outside")
    os.mkfifo(tmp_path / "pipe")
    r = run(
        [
            finding({"uri": "alias"}),
            finding({"uri": "pipe"}),
            finding({"uri": "other", "index": 0}),
            finding({"uri": "src/file"}),
        ]
    )
    r["artifacts"] = [{"location": {"uri": "alias"}}]
    states = [e.locations[0].state for e in inventory(sarif(r), tmp_path).runs[0].entries]
    assert states == [
        "unreadable_file",
        "unreadable_file",
        "conflicting_artifact_reference",
        "missing_file",
    ]
    assert (
        inventory(sarif(r), tmp_path, "src").runs[0].entries[0].locations[0].state
        == "outside_component"
    )


def test_cli_no_overwrite_and_document_rejection(tmp_path: Path) -> None:
    inp = tmp_path / "scan.sarif"
    out = tmp_path / "inventory.json"
    args = ["intake", "--repo", str(tmp_path), "--sarif", str(inp), "--output", str(out)]
    inp.write_text("{")
    assert main(args) == 2 and not out.exists()
    inp.write_bytes(sarif(run([finding({"uri": "missing"})])))
    assert main(args) == 1
    before = out.read_bytes()
    assert main(args) == 2 and out.read_bytes() == before
