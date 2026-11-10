import json
import os
from pathlib import Path

import pytest

from vulnproof.cli import main


def invoke(repo: Path, output: Path, environment: Path, *extra: str) -> int:
    return main(
        [
            "scan",
            "--repo",
            str(repo),
            "--output",
            str(output),
            "--semgrep-environment",
            str(environment),
            *extra,
        ]
    )


def test_reject_unprepared_or_overlapping_tool(tmp_path: Path) -> None:
    repo = tmp_path / "checkout"
    repo.mkdir()
    out = tmp_path / "out"
    assert invoke(repo, out, repo / "tool") == 2
    assert invoke(repo, out, tmp_path / "missing") == 2
    assert not out.exists()


@pytest.mark.parametrize("component", ["../outside", "/tmp", ".git"])
def test_reject_unsafe_component(tmp_path: Path, component: str) -> None:
    assert (
        invoke(tmp_path / "repo", tmp_path / "out", tmp_path / "tool", "--component", component)
        == 2
    )


@pytest.mark.skipif(
    not os.environ.get("VULNPROOF_TEST_SEMGREP"), reason="requires prepared Semgrep"
)
def test_installed_scanner_on_unregistered_checkout(tmp_path: Path) -> None:
    environment = Path(os.environ["VULNPROOF_TEST_SEMGREP"])
    repo = tmp_path / "project"
    component = repo / "packages/search"
    component.mkdir(parents=True)
    (repo / "view.py").write_text('from flask import request\nopen(request.args.get("name"))\n')
    (component / "handler.js").write_text("eval(req.query.text);\n")
    (repo / "notes").mkdir()
    (repo / "notes/info.txt").write_text("Only documentation.")
    (repo / ".semgrepignore").write_text("*\n")
    out = tmp_path / "whole"
    assert invoke(repo, out, environment) == 0
    inv = json.loads((out / "inventory.json").read_text())
    receipt = json.loads((out / "scan.json").read_text())
    assert inv["input_sha256"] == receipt["sarif_sha256"]
    assert inv["result_count"] == 2
    assert set(receipt["scanned_paths"]) == {"view.py", "packages/search/handler.js"}
    assert all(e["locations"][0]["state"] == "present" for e in inv["runs"][0]["entries"])
    assert invoke(repo, out, environment) == 2
    scoped = tmp_path / "scoped"
    assert invoke(repo, scoped, environment, "--component", "packages/search") == 0
    inv = json.loads((scoped / "inventory.json").read_text())
    assert inv["result_count"] == 1
    assert inv["runs"][0]["entries"][0]["locations"][0]["path"] == "packages/search/handler.js"
    empty = tmp_path / "empty"
    assert invoke(repo, empty, environment, "--component", "notes") == 1
    assert json.loads((empty / "scan.json").read_text())["outcome"] == "no_applicable_targets"
    (component / "handler.js").write_text("console.log('hello');\n")
    zero = tmp_path / "zero"
    assert invoke(repo, zero, environment, "--component", "packages/search") == 0
    assert json.loads((zero / "scan.json").read_text())["result_count"] == 0
