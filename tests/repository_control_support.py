"""Synthetic SAST/CodeQL evidence for control orchestration, not analysis accuracy."""

import json
import shutil
from pathlib import Path
from typing import Any

from tests.static_pipeline import location

from vulnproof.correlation.repository import RULE, correlate_repository, prepare_import
from vulnproof.discovery.repository import discover
from vulnproof.models import ToolIdentity
from vulnproof.planning.repository import plan_repository
from vulnproof.runner.repository import (
    ImageConfiguration,
    RepositoryImage,
    driver_bytes,
    recipe,
    sha,
)
from vulnproof.static.models import CODEQL_VERSION, PACK_VERSION, CommandRecord
from vulnproof.static.process import artifact
from vulnproof.static.repository import Investigation, ScanInput
from vulnproof.static.sarif import normalize_sarif


def control_inputs(
    root: Path, module: str = "exports/web.py", mode: str = "normal"
) -> dict[str, Any]:
    checkout = root / "checkout"
    target = checkout / module
    target.parent.mkdir(parents=True)
    (target.parent / "__init__.py").touch()
    (target.parent / "helper.py").write_text("suffix = b''\n")
    expression = "open(name, 'rb').read() + suffix"
    if mode in ("send_file", "send_directory", "send_file_keyword", "send_directory_keyword"):
        expression = {
            "send_file": "deliver(name)",
            "send_file_keyword": "deliver(path_or_file=name)",
            "send_directory": "from_dir('/application', name)",
            "send_directory_keyword": "from_dir(directory='/application', path=name)",
        }[mode]
    if mode == "redirect":
        expression += ", 302, {'Location': '/must-not-follow'}"
    source = (
        "from flask import Flask, request\nfrom .helper import suffix\n"
        "service = Flask(__name__)\n@service.get('/export')\ndef export():\n"
        "    name = request.args.get('document')\n    return " + expression + "\n"
    )
    if mode in ("send_file", "send_directory", "send_file_keyword", "send_directory_keyword"):
        source = source.replace(
            "from flask import Flask, request",
            "from flask import Flask, request, send_file as deliver, send_from_directory as from_dir",
        )
    if mode in ("route", "route_patched"):
        source = (
            source.replace(
                "@service.get('/export')",
                "@service.route('/export/<path:document>', methods=['GET'])",
            )
            .replace("def export():", "def export(document):")
            .replace("name = request.args.get('document')", "name = document")
        )
        if mode == "route_patched":
            source = source.replace(
                "return " + expression,
                "return " + expression + " if name == 'manual.txt' else ('missing', 404)",
            )
    additions = {
        "import_failed": "raise RuntimeError('synthetic import failure')\n",
        "startup_timeout": "import time\ntime.sleep(30)\n",
        "factory": "service = lambda: None\n",
        "debug": "service.debug = True\n",
        "missing_symbol": "del service\n",
        "request_timeout": "@service.before_request\ndef delay():\n    import time\n    time.sleep(10)\n",
        "patched": "@service.before_request\ndef restrict():\n    if request.args.get('document') != 'manual.txt':\n        from flask import abort\n        abort(404)\n",
        "fixed_query": "@service.before_request\ndef require_fixed():\n    from flask import abort\n    if request.args.get('model') != 'demo & ü' or request.args.get('version') != '':\n        abort(400)\n",
        "noise": "print('application stdout is separate')\n",
        "flood": "print('x' * (2 * 1024 * 1024), flush=True)\n",
    }
    target.write_text(
        source
        + (
            additions["fixed_query"]
            if mode in ("route", "route_patched")
            else additions.get(mode, "")
        )
    )
    body = b"manual\n" if mode != "large" else b"x" * 65537
    (checkout / "manual.txt").write_bytes(body)
    if mode in ("send_file", "send_file_keyword"):
        (target.parent / "manual.txt").write_bytes(body)
    sink_start = source.splitlines()[6].index("name") + 1
    scanner = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Semgrep OSS"}},
                "results": [
                    {
                        "ruleId": "vulnproof.repository.route-file-read"
                        if mode in ("route", "route_patched")
                        else {
                            "send_file": "vulnproof.repository.send-file",
                            "send_directory": "vulnproof.repository.send-from-directory",
                            "send_file_keyword": "vulnproof.repository.send-file",
                            "send_directory_keyword": "vulnproof.repository.send-from-directory",
                        }.get(mode, RULE),
                        "message": {"text": "Synthetic control test finding"},
                        "locations": [
                            location(
                                7, uri=module, start_column=sink_start, end_column=sink_start + 4
                            )
                        ],
                    }
                ],
            }
        ],
    }
    scan = root / "scan"
    prepare_import(checkout, None, json.dumps(scanner).encode(), scan)
    manifest = ScanInput.model_validate_json((scan / "scan.json").read_bytes())
    analysis = root / "investigation"
    (analysis / "diagnostics").mkdir(parents=True)
    (analysis / "work").mkdir()
    shutil.copytree(scan / "snapshot", analysis / "work/source")
    raw: dict[str, Any] = {
        "version": "2.1.0",
        "runs": [
            {
                "columnKind": "unicodeCodePoints",
                "tool": {"driver": {"name": "CodeQL", "semanticVersion": CODEQL_VERSION}},
                "results": [
                    {
                        "ruleId": "py/path-injection",
                        "locations": [
                            location(
                                7, uri=module, start_column=sink_start, end_column=sink_start + 4
                            )
                        ],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": location(
                                                    6, uri=module, start_column=12, end_column=40
                                                )
                                            },
                                            {
                                                "location": location(
                                                    7,
                                                    uri=module,
                                                    start_column=sink_start,
                                                    end_column=sink_start + 4,
                                                )
                                            },
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ],
            }
        ],
    }
    if mode in ("route", "route_patched"):
        raw["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"][0][
            "location"
        ] = location(5, uri=module, start_column=12, end_column=20)
    raw_path = analysis / "diagnostics/raw.sarif"
    raw_path.write_text(json.dumps(raw))
    results, notes = normalize_sarif(
        raw_path.read_bytes(), analysis / "work/source", manifest.files
    )
    commands = []
    for stage in ("version", "extract", "query"):
        log = analysis / f"diagnostics/{stage}.log"
        log.write_text("Synthetic evidence, tools not executed\n")
        commands.append(
            CommandRecord.model_validate(
                {
                    "stage": stage,
                    "outcome": "completed",
                    "return_code": 0,
                    "duration_seconds": 0,
                    "log": artifact(log, analysis, f"log:{stage}"),
                }
            )
        )
    investigation = Investigation(
        scan_sha256=sha((scan / "scan.json").read_bytes()),
        source_fingerprint=manifest.source_fingerprint,
        component=None,
        tool=ToolIdentity(
            name="CodeQL", version=CODEQL_VERSION, rule_pack="codeql/python-queries@" + PACK_VERSION
        ),
        outcome="completed",
        results=results,
        diagnostics=notes,
        commands=tuple(commands),
        raw_sarif=artifact(raw_path, analysis, "sarif:raw"),
    )
    (analysis / "investigation.json").write_text(investigation.model_dump_json())
    links, discovery, config, plan = [
        root / n for n in ("links.json", "discovery.json", "endpoint.json", "plan.json")
    ]
    links.write_text(correlate_repository(scan, analysis))
    discovery.write_text(discover(scan, analysis, links))
    expected = sha(b"different") if mode == "wrong_body" else sha(body)
    config.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "endpoints": [
                    {
                        "file": module,
                        "handler": "export",
                        "entry_point": module + ":service",
                        "download_root": "/application",
                        "control_value": "manual.txt",
                        "control_sha256": expected,
                    }
                ],
            }
        )
    )
    if mode in ("send_file", "send_file_keyword"):
        settings = json.loads(config.read_bytes())
        settings["endpoints"][0]["download_root"] = "/application/" + str(Path(module).parent)
        config.write_text(json.dumps(settings))
    if mode in ("route", "route_patched"):
        settings = json.loads(config.read_bytes())
        settings["schema_version"] = "1.2"
        settings["endpoints"][0]["path_parameter"] = "document"
        settings["endpoints"][0]["fixed_query"] = [
            {"name": "model", "value": "demo & ü"},
            {"name": "version", "value": ""},
        ]
        config.write_text(json.dumps(settings))
    if mode == "fixed_query":
        settings = json.loads(config.read_bytes())
        settings["schema_version"] = "1.1"
        settings["endpoints"][0]["fixed_query"] = [
            {"name": "model", "value": "demo & ü"},
            {"name": "version", "value": ""},
        ]
        config.write_text(json.dumps(settings))
    plan.write_text(plan_repository(scan, analysis, links, discovery, config))
    data = json.loads(plan.read_bytes())
    row = data["findings"][0]
    assert row["status"] == "draft", row
    prepared = root / "prepared"
    prepared.mkdir()
    image_config = ImageConfiguration.model_validate(
        {
            "schema_version": "1.0",
            "entry_point": module + ":service",
            "platform": "linux/arm64",
            "wheels": ({"filename": "demo-1.0-py3-none-any.whl", "sha256": "a" * 64},),
        }
    )
    requirements = (
        f"/opt/vulnproof/wheels/demo-1.0-py3-none-any.whl --hash=sha256:{'a' * 64}\n".encode()
    )
    from vulnproof.runner.repository import BASE

    record = RepositoryImage(
        scan_sha256=sha((scan / "scan.json").read_bytes()),
        source_fingerprint=manifest.source_fingerprint,
        configuration_sha256="a" * 64,
        configuration=image_config,
        recipe_sha256=sha(recipe()),
        requirements_sha256=sha(requirements),
        base_image=BASE,
        image_id="sha256:" + "a" * 64,
        entry_point_file=module,
        driver_sha256=sha(driver_bytes()),
    )
    preparation = prepared / "prepared-image.json"
    preparation.write_text(record.model_dump_json())
    return dict(
        scan=scan,
        investigation=analysis,
        correlation=links,
        discovery=discovery,
        config=config,
        plan=plan,
        preparation=preparation,
        finding_id=row["finding_id"],
        socket=Path("/docker.sock"),
        output=root / "attempt",
        authorize_execution=True,
    )
