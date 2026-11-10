import json
import os
import shutil
from pathlib import Path

import pytest

from vulnproof.cli import main
from vulnproof.static.process import artifact
from vulnproof.static.repository import Investigation, ScanInput
from vulnproof.static.sarif import normalize_sarif


def correlate(scan: Path, analysis: Path, out: Path) -> int:
    return main(
        [
            "correlate-repository",
            "--scan",
            str(scan),
            "--investigation",
            str(analysis),
            "--output",
            str(out),
        ]
    )


@pytest.mark.skipif(
    not (os.environ.get("VULNPROOF_TEST_SEMGREP") and os.environ.get("VULNPROOF_TEST_CODEQL")),
    reason="requires pinned tools",
)
def test_repository_findings(tmp_path: Path) -> None:
    repo = tmp_path / "checkout"
    repo.mkdir()
    (repo / "handlers.py").write_text(
        "from flask import Flask, request\napp = Flask(__name__)\n@app.get('/download')\ndef route():\n"
        "    name = request.args.get('name')\n    return open(name).read() + open(name).read()\n"
    )
    (repo / "client.js").write_text("eval(req.query.text);\n")
    scan = tmp_path / "local"
    assert (
        main(
            [
                "scan",
                "--repo",
                str(repo),
                "--output",
                str(scan),
                "--semgrep-environment",
                os.environ["VULNPROOF_TEST_SEMGREP"],
            ]
        )
        == 0
    )
    for origin in ("local", "import"):
        selected = tmp_path / origin
        if origin == "import":
            sarif = json.loads((scan / "diagnostics/raw.sarif").read_bytes())
            results = sarif["runs"][0]["results"]
            broad = next(r for r in results if r["ruleId"].endswith("file-read"))
            broad["locations"][0]["physicalLocation"]["region"] = {"startLine": 6}

            results.append(dict(broad, locations=[]))
            results.append(
                dict(
                    broad,
                    locations=[
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "handlers.py"},
                                "region": {"startLine": 5},
                            }
                        }
                    ],
                )
            )
            report = tmp_path / "external.sarif"
            report.write_text(json.dumps(sarif))
            assert (
                main(
                    [
                        "prepare-repository",
                        "--repo",
                        str(repo),
                        "--sarif",
                        str(report),
                        "--output",
                        str(selected),
                    ]
                )
                == 0
            )
        investigation = tmp_path / (origin + "-analysis")
        assert (
            main(
                [
                    "investigate",
                    "--scan",
                    str(selected),
                    "--codeql-bundle",
                    os.environ["VULNPROOF_TEST_CODEQL"],
                    "--output",
                    str(investigation),
                ]
            )
            == 0
        )
        out = tmp_path / (origin + ".json")
        assert correlate(selected, investigation, out) == 0
        evidence = json.loads(out.read_text())
        assert evidence["counts"]["unsupported_mapping"] == 1
        if origin == "local":
            assert evidence["counts"]["single_candidate"] == 2
            assert evidence["scanner_source_state"] == "controlled_snapshot"
        else:
            assert evidence["scanner_source_state"] == "unverified"
            assert evidence["counts"] == {
                "unsupported_mapping": 1,
                "single_candidate": 1,
                "ambiguous": 1,
                "location_unavailable": 1,
                "no_candidate": 1,
            }
        if origin == "local":
            # Model a partial tool report with two valid alternative flows to one sink.
            partial = tmp_path / "partial"
            shutil.copytree(
                investigation,
                partial,
                ignore=shutil.ignore_patterns("database", "cache", "tmp", "home"),
            )
            raw_path = partial / "diagnostics/raw.sarif"
            codeql = json.loads(raw_path.read_bytes())
            run = codeql["runs"][0]
            flows = run["results"][0]["codeFlows"]
            flows.append(flows[0])
            run["invocations"] = [
                {
                    "executionSuccessful": True,
                    "toolExecutionNotifications": [
                        {"level": "warning", "message": {"text": "Synthetic coverage warning"}}
                    ],
                }
            ]
            raw_path.write_text(json.dumps(codeql))
            normalized = Investigation.model_validate_json(
                (partial / "investigation.json").read_bytes()
            )
            manifest = ScanInput.model_validate_json((scan / "scan.json").read_bytes()).files
            normalized.results, normalized.diagnostics = normalize_sarif(
                raw_path.read_bytes(), partial / "work/source", manifest
            )
            normalized.outcome = "partial"
            normalized.raw_sarif = artifact(raw_path, partial, "sarif:raw")
            (partial / "investigation.json").write_text(normalized.model_dump_json())
            partial_out = tmp_path / "partial.json"
            assert correlate(scan, partial, partial_out) == 0
            linked = json.loads(partial_out.read_bytes())
            assert linked["analysis_outcome"] == "partial" and linked["analysis_diagnostics"]
            assert linked["counts"] == evidence["counts"]
            assert any(
                len(ids) > 1 for row in linked["findings"] for ids in row["candidates"].values()
            )
        inventory = selected / "inventory.json"
        inventory.write_text("{}")
        assert correlate(selected, investigation, tmp_path / "rejected") == 2
        assert not (tmp_path / "rejected").exists()


def test_prior_inventory_rechecked_and_failed_analysis_accounted(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "handler.py"
    source.write_text("open(name)\n")
    result = {
        "ruleId": "vulnproof.repository.request-file-read",
        "message": {"text": "file open"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "handler.py"},
                    "region": {"startLine": 1},
                }
            }
        ],
    }
    raw = tmp_path / "report.sarif"
    raw.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {"tool": {"driver": {"name": "Semgrep OSS"}}, "results": [result, result]}
                ],
            }
        )
    )
    inventory = tmp_path / "inventory.json"
    assert (
        main(["intake", "--repo", str(repo), "--sarif", str(raw), "--output", str(inventory)]) == 0
    )
    args = ["prepare-repository", "--repo", str(repo), "--inventory", str(inventory), "--output"]
    scan = tmp_path / "snapshot"
    assert main([*args, str(scan)]) == 0
    source.write_text("edited\n")
    assert main([*args, str(tmp_path / "changed")]) == 2
    analysis = tmp_path / "failed"
    assert (
        main(
            [
                "investigate",
                "--scan",
                str(scan),
                "--output",
                str(analysis),
                "--codeql-bundle",
                str(tmp_path / "missing"),
            ]
        )
        == 1
    )
    out = tmp_path / "links.json"
    assert correlate(scan, analysis, out) == 0
    data = json.loads(out.read_text())
    assert data["counts"] == {"analysis_failed": 2}
    first, second = data["findings"]
    assert second["finding"]["duplicate_of"] == first["finding"]["id"]
