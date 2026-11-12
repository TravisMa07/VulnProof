"""Synthetic scanner/CodeQL evidence for contract tests; not actual-tool demonstrations."""

import json
import shutil
from pathlib import Path
from typing import Any

from scripts.check_injection_benchmark import endpoint

from vulnproof.correlation.repository import prepare_import
from vulnproof.injections.models import Capability
from vulnproof.injections.planning import digest, sink_arguments
from vulnproof.investigation.capabilities import INJECTION_QUERIES
from vulnproof.models import ToolIdentity
from vulnproof.onboarding.planning import verified_scan
from vulnproof.static.models import CommandRecord
from vulnproof.static.process import artifact
from vulnproof.static.repository import Investigation
from vulnproof.static.sarif import normalize_sarif

ROOT = Path(__file__).resolve().parents[1]


def inputs(root: Path, kind: Capability = "command") -> dict[str, Any]:
    source = root / "checkout"
    file = f"{kind}/vulnerable/app.py"
    target = source / file
    target.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "fixtures/injections" / file, target)
    sink = sink_arguments(source, file, kind)[0]

    def location(line: int, column: int | None = None, end: int | None = None) -> dict[str, Any]:
        return dict(
            physicalLocation=dict(
                artifactLocation=dict(uri=file),
                region={
                    "startLine": line,
                    **({"startColumn": column, "endColumn": end} if column else {}),
                },
            )
        )

    raw = dict(
        version="2.1.0",
        runs=[
            dict(
                tool=dict(driver=dict(name="Semgrep OSS", version="1.184.0")),
                columnKind="unicodeCodePoints",
                results=[
                    dict(
                        ruleId=f"vulnproof.repository.{kind}-injection",
                        message=dict(text="Synthetic contract test"),
                        locations=[location(sink.start_line, sink.start_column, sink.end_column)],
                    )
                ],
            )
        ],
    )
    scan = root / "scan"
    prepare_import(source, None, json.dumps(raw).encode(), scan)
    raw_scan, manifest = verified_scan(scan)
    query = INJECTION_QUERIES[kind]
    lines = target.read_text().splitlines()
    request_import = next(
        n for n, line in enumerate(lines, 1) if line.startswith("from flask import")
    )
    request_use = next(n for n, line in enumerate(lines, 1) if "request.args.get" in line)
    loc = location(sink.start_line, sink.start_column, sink.end_column)
    codeql = dict(
        version="2.1.0",
        runs=[
            dict(
                tool=dict(driver=dict(name="CodeQL", semanticVersion="2.27.3")),
                results=[
                    dict(
                        ruleId=query.id,
                        locations=[loc],
                        codeFlows=[
                            dict(
                                threadFlows=[
                                    dict(
                                        locations=[
                                            dict(location=v)
                                            for v in [
                                                location(request_import),
                                                location(request_use),
                                                loc,
                                            ]
                                        ]
                                    )
                                ]
                            )
                        ],
                    )
                ],
            )
        ],
    )
    directory = root / "analysis"
    (directory / "diagnostics").mkdir(parents=True)
    raw_sarif = directory / "diagnostics/raw.sarif"
    raw_sarif.write_text(json.dumps(codeql))
    normalized, notes = normalize_sarif(
        raw_sarif.read_bytes(), scan / "snapshot", manifest.files, query.id
    )
    commands = []
    for stage in ("version", "extract", "query"):
        path = directory / "diagnostics" / f"{stage}.log"
        path.write_text("Synthetic test tool boundary\n")
        commands.append(
            CommandRecord(
                stage=stage,
                outcome="completed",
                return_code=0,
                duration_seconds=0,
                log=artifact(path, directory, "log:" + stage),
            )
        )
    report = Investigation(
        scan_sha256=digest(raw_scan),
        source_fingerprint=manifest.source_fingerprint,
        component=None,
        query_id=query.id,
        query_sha256=query.sha256,
        tool=ToolIdentity(
            name="CodeQL", version="2.27.3", rule_pack="codeql/python-queries@1.8.13"
        ),
        outcome="completed",
        results=normalized,
        commands=tuple(commands),
        raw_sarif=artifact(raw_sarif, directory, "sarif:raw"),
        diagnostics=notes,
    )
    (directory / "investigation.json").write_text(report.model_dump_json())
    config = root / "config.json"
    config.write_text(
        json.dumps(dict(schema_version="1.0", endpoints=[endpoint(kind, "vulnerable")]))
    )
    return dict(scan=scan, investigations={kind: directory}, config=config)


def rewrite_codeql(args: dict[str, Any], change: str) -> None:
    directory = next(iter(args["investigations"].values()))
    path = directory / "diagnostics/raw.sarif"
    document = json.loads(path.read_text())
    results = document["runs"][0]["results"]
    if change == "ambiguous":
        results.append(results[0])
    if change == "no_path":
        results[0]["codeFlows"] = []
    path.write_text(json.dumps(document))
    raw, manifest = verified_scan(args["scan"])
    report = Investigation.model_validate_json((directory / "investigation.json").read_bytes())
    normalized, notes = normalize_sarif(
        path.read_bytes(), args["scan"] / "snapshot", manifest.files, report.query_id
    )
    report.results = normalized
    report.diagnostics = notes
    report.raw_sarif = artifact(path, directory, "sarif:raw")
    report.outcome = "partial" if notes or any(r.diagnostics for r in normalized) else "completed"
    (directory / "investigation.json").write_text(report.model_dump_json())
