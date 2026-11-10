import json
import os
from pathlib import Path

import pytest

from vulnproof.cli import main
from vulnproof.discovery.flask import parse_module


@pytest.mark.parametrize(
    ("declaration", "route", "reason"),
    [
        ("from registration import app", "'/file'", "application_registration_unresolved"),
        ("app = Flask(__name__)", "configured_route", "route_unresolved"),
    ],
)
def test_incomplete_registration(declaration: str, route: str, reason: str) -> None:
    source = f"from flask import Flask, request\n{declaration}\n@app.get({route})\ndef page():\n    return request.args.get('key')\n"
    handlers = parse_module("renamed/site.py", source.encode()).handlers
    assert reason in handlers[0].gaps


@pytest.mark.skipif(
    not (os.environ.get("VULNPROOF_TEST_SEMGREP") and os.environ.get("VULNPROOF_TEST_CODEQL")),
    reason="requires pinned tools",
)
def test_discover_real_cross_file_route(tmp_path: Path) -> None:
    repo = tmp_path / "checkout"
    pkg = repo / "exports"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").touch()
    (pkg / "web.py").write_text(
        "from flask import Flask, request\nfrom exports.files import read\nservice = Flask(__name__)\n"
        "@service.get('/export')\ndef export():\n    return read(request.args.get('document'))\n"
        "@service.get('/manual')\ndef manual():\n    return read('manual.txt')\n"
        "raise RuntimeError('discovery must never import this module')\n"
    )
    (pkg / "files.py").write_text(
        "from flask import request\ndef read(name):\n    if not name:\n        name = request.args.get('fallback')\n    return open(name, 'rb').read()\n"
    )
    scan, analysis, links, out = [
        tmp_path / name for name in ("scan", "analysis", "links.json", "discovery.json")
    ]
    assert (
        main(
            [
                "scan",
                "--repo",
                str(repo),
                "--semgrep-environment",
                os.environ["VULNPROOF_TEST_SEMGREP"],
                "--output",
                str(scan),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "investigate",
                "--scan",
                str(scan),
                "--codeql-bundle",
                os.environ["VULNPROOF_TEST_CODEQL"],
                "--output",
                str(analysis),
            ]
        )
        == 0
    )
    args = ["--scan", str(scan), "--investigation", str(analysis)]
    assert main(["correlate-repository", *args, "--output", str(links)]) == 0
    command = ["discover-repository", *args, "--correlation", str(links), "--output"]
    assert main([*command, str(out)]) == 0
    result = json.loads(out.read_bytes())
    bindings = [b for p in result["paths"].values() for b in p["bindings"]]
    assert {b["handler"] for b in bindings} == {"export"}
    match = next(b for b in bindings if b["inputs"])
    assert match["application_symbol"] == "service"
    assert match["application_location"]["path"] == "exports/web.py"
    assert [(r["method"], r["path"]) for r in match["routes"]] == [("GET", "/export")]
    assert [i["name"] for i in match["inputs"]] == ["document"]
    assert not match["gaps"]
    edited = json.loads(links.read_text())
    edited["findings"] = []
    links.write_text(json.dumps(edited))
    assert main([*command, str(tmp_path / "invalid")]) == 2


def test_location_in_handler_requires_specific_input_evidence() -> None:
    from vulnproof.discovery.repository import binding
    from vulnproof.models import SourceLocation

    source = b"from flask import Flask, request\napi=Flask(__name__)\n@api.route('/test',methods=['POST'])\ndef serve():\n    first=request.args.get('a'); second=request.args.get('b')\n    def nested():\n        return first\n    return second\n"
    handlers = parse_module("other/renamed.py", source).handlers
    handler = handlers[0]
    inputs = dict(handler.inputs)
    observed = binding(handler, [inputs["b"]])
    assert observed and observed["inputs"] == [
        {"kind": "query", "name": "b", "location": inputs["b"].model_dump()}
    ]
    coarse = binding(handler, [SourceLocation(path="other/renamed.py", start_line=5)])
    assert coarse and coarse["gaps"] == ["query_parameter_unresolved"]
    assert binding(handler, [SourceLocation(path="other/renamed.py", start_line=7)]) is None
