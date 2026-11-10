import json
import os
from pathlib import Path

import pytest

from vulnproof.cli import main
from vulnproof.provenance.filesystem import open_root, scan_tree
from vulnproof.provenance.models import fingerprint


def invoke(scan: Path, out: Path, bundle: Path) -> int:
    return main(
        ["investigate", "--scan", str(scan), "--output", str(out), "--codeql-bundle", str(bundle)]
    )


def test_unsupported_and_modified_snapshot(tmp_path: Path) -> None:
    scan = tmp_path / "scan"
    source = scan / "snapshot"
    source.mkdir(parents=True)
    (source / "client.js").write_text("let x = 1;")
    with open_root(source) as fd:
        manifest = scan_tree(fd).files
    (scan / "scan.json").write_text(
        json.dumps(
            {
                "profile": "repository-scan-v1",
                "schema_version": "1.0",
                "outcome": "completed",
                "component": None,
                "source_fingerprint": fingerprint(manifest),
                "files": [f.model_dump() for f in manifest],
            }
        )
    )
    for name, expected in (("first", "unsupported"), ("second", "failed")):
        out = tmp_path / name
        assert invoke(scan, out, tmp_path / "absent-tool") == 1
        report = json.loads((out / "investigation.json").read_text())
        assert report["outcome"] == expected and report["commands"] == []
        if name == "second":
            assert report["diagnostics"][0]["code"] == "source_changed"
        (source / "client.js").write_text("changed")


@pytest.mark.skipif(
    not (os.environ.get("VULNPROOF_TEST_SEMGREP") and os.environ.get("VULNPROOF_TEST_CODEQL")),
    reason="requires prepared Semgrep and CodeQL",
)
def test_cross_file_path_after_original_changes(tmp_path: Path) -> None:
    project = tmp_path / "project"
    package = project / "service"
    package.mkdir(parents=True)
    (package / "__init__.py").touch()
    (package / "routes.py").write_text(
        "from flask import Flask, request\nfrom service.storage import load\napp = Flask(__name__)\n"
        "@app.get('/download')\ndef download():\n    return load(request.args.get('name'))\n"
    )
    helper = package / "storage.py"
    helper.write_text("def load(name):\n    return open(name, 'rb').read()\n")
    scan = tmp_path / "scan"
    assert (
        main(
            [
                "scan",
                "--repo",
                str(project),
                "--output",
                str(scan),
                "--semgrep-environment",
                os.environ["VULNPROOF_TEST_SEMGREP"],
            ]
        )
        == 0
    )
    helper.write_text("def load(name):\n    return b''\n")
    out = tmp_path / "investigation"
    assert invoke(scan, out, Path(os.environ["VULNPROOF_TEST_CODEQL"])) == 0
    report = json.loads((out / "investigation.json").read_text())
    assert [c["stage"] for c in report["commands"]] == ["version", "extract", "query"]
    assert any(
        nodes[-1]["path"] == "service/storage.py"
        and any(n["path"] == "service/routes.py" for n in nodes)
        for result in report["results"]
        for path in result["paths"]
        for nodes in [path["path"]["locations"]]
    )
