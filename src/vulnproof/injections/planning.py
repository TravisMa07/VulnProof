"""Reconstruct retained evidence and account for every SARIF occurrence without execution."""

import ast
import hashlib
import json
from dataclasses import asdict
from importlib.resources import files
from pathlib import Path
from typing import Any

from vulnproof.artifacts import read_local
from vulnproof.correlation.engine import _artifact
from vulnproof.correlation.file_reads import overlaps
from vulnproof.correlation.repository import ColumnUnits, region, snapshot_inventory
from vulnproof.discovery.flask import parse_module
from vulnproof.investigation.capabilities import INJECTION_QUERIES, INJECTION_RULES
from vulnproof.models import SourceLocation
from vulnproof.onboarding.planning import read, verified_scan
from vulnproof.planning.repository import unique_fields
from vulnproof.scanning.engine import scan_profile
from vulnproof.scanning.models import VERSION, ScanCommand
from vulnproof.scanning.repository import scanned_paths, successful_invocation
from vulnproof.static.models import CODEQL_VERSION, MAX_LOG_BYTES, MAX_SARIF_BYTES, QueryResult
from vulnproof.static.repository import Investigation
from vulnproof.static.sarif import normalize_sarif

from .models import Capability, Configuration, Endpoint, Entry, Plans

LIMIT = 64 * 1024 * 1024


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entry_record(data: dict[str, Any]) -> Entry:
    return Entry.model_validate_json(json.dumps(data, default=lambda v: v.model_dump(mode="json")))


def sink_arguments(root: Path, path: str, capability: Capability) -> list[SourceLocation]:
    data = read_local(root, path, 256 * 1024)
    # The discovery parser imposes bounds before ast.parse and resolves Flask request imports.
    if parse_module(path, data).issue:
        return []
    try:
        text = data.decode("utf-8")
        tree = ast.parse(text)
    except SyntaxError, UnicodeError, RecursionError:
        return []
    imports = {}
    node: ast.AST
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.update({a.asname or a.name: a.name for a in node.names})
        if isinstance(node, ast.ImportFrom) and not node.level:
            imports.update({a.asname or a.name: f"{node.module}.{a.name}" for a in node.names})
    shadowed = {
        n.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))
    }
    shadowed.update(n.arg for n in ast.walk(tree) if isinstance(n, ast.arg))
    imports = {k: v for k, v in imports.items() if k not in shadowed}
    lines = text.splitlines()
    result = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = ""
        if isinstance(node.func, ast.Name):
            name = imports.get(node.func.id, "")
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            name = imports.get(node.func.value.id, "") + "." + node.func.attr
        supported = (
            capability == "command"
            and (
                name == "os.system"
                or name in {"subprocess.check_output", "subprocess.run"}
                and any(
                    k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                    for k in node.keywords
                )
            )
            or capability == "template"
            and name == "flask.render_template_string"
            or capability == "sql"
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
        )
        if supported:
            arg = node.args[0]
            line, end = arg.lineno, arg.end_lineno or arg.lineno
            result.append(
                SourceLocation(
                    path=path,
                    start_line=line,
                    end_line=end,
                    start_column=len(lines[line - 1].encode()[: arg.col_offset].decode()) + 1,
                    end_column=len(lines[end - 1].encode()[: arg.end_col_offset].decode()) + 1,
                )
            )
    return result


def verified_investigation(scan: Path, directory: Path, key: str) -> tuple[bytes, Investigation]:
    raw = read_local(directory, "investigation.json", LIMIT)
    report = Investigation.model_validate_json(raw)
    scan_raw, selected = verified_scan(scan)
    query = INJECTION_QUERIES[key]
    if (
        report.scan_sha256 != digest(scan_raw)
        or report.source_fingerprint != selected.source_fingerprint
        or report.component != selected.component
        or report.query_id != query.id
        or report.query_sha256 != query.sha256
    ):
        raise ValueError("Investigation identity mismatch")
    for command in report.commands:
        _artifact(directory, command.log, MAX_LOG_BYTES)
    if report.outcome in ("completed", "partial"):
        if (
            report.tool is None
            or report.tool.name != "CodeQL"
            or report.tool.version != CODEQL_VERSION
            or report.tool.rule_pack != "codeql/python-queries@1.8.13"
            or tuple(c.stage for c in report.commands) != ("version", "extract", "query")
            or any(
                c.outcome != "completed" or c.return_code != 0 or c.log.truncated
                for c in report.commands
            )
            or report.raw_sarif is None
            or report.raw_sarif.truncated
        ):
            raise ValueError("Incomplete static evidence")
        sarif = _artifact(directory, report.raw_sarif, MAX_SARIF_BYTES)
        normalized, diagnostics = normalize_sarif(
            sarif, scan / "snapshot", selected.files, query.id
        )
        if normalized != report.results or diagnostics != report.diagnostics:
            raise ValueError("Edited normalized CodeQL evidence")
    elif report.results:
        raise ValueError("Unsuccessful analysis cannot supply usable paths")
    return raw, report


def endpoint_paths(root: Path, result: QueryResult, endpoint: Endpoint) -> tuple[str, ...]:
    module = parse_module(endpoint.file, read_local(root, endpoint.file, 256 * 1024))
    supported = []
    for handler in module.handlers:
        if handler.name != endpoint.handler or handler.gaps:
            continue
        if not any(r.method == "GET" and r.path == endpoint.request.route for r in handler.routes):
            continue
        inputs = [loc for key, loc in handler.inputs if key == endpoint.request.query_key]
        for path in result.paths:
            nodes = path.path.locations
            if any(overlaps(loc, node) for loc in inputs for node in nodes) and (
                any(overlaps(nodes[0], loc) for loc in inputs)
                or nodes[0].path == endpoint.file
                and nodes[0].start_line in module.request_import_lines
            ):
                supported.append(path.path.id)
    return tuple(sorted(set(supported)))


def plan_injections(scan: Path, investigations: dict[str, Path], config: Path | None) -> Plans:
    raw, selected = verified_scan(scan)
    metadata = json.loads(raw)
    source = scan / "snapshot"
    sarif = read_local(scan, "diagnostics/raw.sarif", MAX_SARIF_BYTES)
    inv = snapshot_inventory(sarif, source, selected.component)
    if digest(sarif) != metadata.get("sarif_sha256") or json.loads(
        read_local(scan, "inventory.json", LIMIT)
    ) != asdict(inv):
        raise ValueError("Scanner inventory mismatch")
    controlled = selected.profile == "repository-scan-v1"
    if controlled and metadata.get("rules_sha256") != digest(
        files("vulnproof.scanning").joinpath("repository.yaml").read_bytes()
    ):
        raise ValueError("Unknown injection scanner profile; imported reports remain unverified")
    if controlled:
        commands = tuple(
            ScanCommand.model_validate_json(json.dumps(c)) for c in metadata.get("commands", [])
        )
        if (
            metadata.get("semgrep_version") != VERSION
            or metadata.get("tool_lock_sha256") != scan_profile().lock_sha256
            or tuple(c.stage for c in commands) != ("version", "scan")
            or any(c.outcome != "completed" or c.return_code != 0 for c in commands)
            or len(inv.runs) != 1
            or inv.runs[0].version != VERSION
        ):
            raise ValueError("Controlled scan lacks complete pinned tool identity")
        for command in commands:
            _artifact(scan, command.stdout, MAX_LOG_BYTES)
            _artifact(scan, command.stderr, MAX_LOG_BYTES)
        actual, errors = scanned_paths(scan)
        expected = {f.path for f in selected.files if Path(f.path).suffix in {".py", ".js"}}
        if selected.outcome == "completed" and (
            actual != expected or errors or not successful_invocation(inv)
        ):
            raise ValueError("Controlled scan coverage mismatch")
    configuration_raw = read(config, LIMIT) if config else None
    configuration = (
        Configuration.model_validate_json(
            json.dumps(json.loads(configuration_raw, object_pairs_hook=unique_fields))
        )
        if configuration_raw
        else Configuration()
    )
    if any(key not in INJECTION_QUERIES for key in investigations):
        raise ValueError("Unknown investigation")
    reports = {
        key: verified_investigation(scan, value, key) for key, value in investigations.items()
    }
    if len(reports) != len(investigations) or any(
        key not in INJECTION_QUERIES for key in investigations
    ):
        raise ValueError("Unknown investigation")
    node_count = sum(
        len(p.path.locations)
        for _, report in reports.values()
        for r in report.results
        for p in r.paths
    )
    comparisons = inv.result_count * sum(len(report.results) for _, report in reports.values())
    if comparisons > 1_000_000 or node_count * max(1, len(configuration.endpoints)) > 1_000_000:
        raise ValueError("Injection planning comparison limit exceeded")
    raw_runs = json.loads(sarif)["runs"]
    columns = ColumnUnits(source)
    entries = []
    for run in inv.runs:
        for occurrence in run.entries:
            base = dict(
                finding_id=occurrence.id,
                original_ref=occurrence.original_ref,
                rule_id=occurrence.rule_id,
                duplicate_of=occurrence.duplicate_of,
            )
            key = next(
                (
                    k
                    for k in INJECTION_QUERIES
                    if run.scanner == INJECTION_RULES[k].producer
                    and occurrence.rule_id == INJECTION_RULES[k].rule_id
                ),
                None,
            )
            reasons = []
            if key is None:
                entries.append(entry_record({**base, "reasons": ["unsupported_scanner_rule"]}))
                continue
            # Literal assignment keeps the persisted capability constrained by its model.
            base["capability"] = key
            if occurrence.suppressed or occurrence.issues or len(occurrence.locations) != 1:
                reasons.append("scanner_occurrence_unusable")
            report = reports.get(key)
            if selected.outcome != "completed":
                reasons.append("scan_incomplete")
            if report is None:
                reasons.append("analysis_missing")
            elif report[1].outcome != "completed":
                reasons.append("analysis_" + report[1].outcome)
            elif report[1].diagnostics or any(r.diagnostics for r in report[1].results):
                reasons.append("analysis_partial")
            if reasons:
                entries.append(entry_record({**base, "reasons": reasons}))
                continue
            assert report is not None
            loc = occurrence.locations[0]
            raw_result = raw_runs[run.index]["results"][
                int(occurrence.original_ref.rsplit("/", 1)[-1])
            ]
            locations = raw_result.get("locations", [])
            site = region(loc, locations[0]) if locations else None
            site = (
                columns.normalize(site, raw_runs[run.index].get("columnKind", "utf16CodeUnits"))
                if site
                else None
            )
            candidates = []
            for result in report[1].results:
                if (
                    result.sink
                    and site
                    and overlaps(result.sink, site)
                    and not result.diagnostics
                    and result.paths
                ):
                    arguments = sink_arguments(source, result.sink.path, key)  # type: ignore[arg-type]
                    if any(overlaps(a, result.sink) and overlaps(a, site) for a in arguments):
                        candidates.append(result)
            if len(candidates) != 1:
                entries.append(
                    entry_record(
                        {
                            **base,
                            "reasons": [
                                "ambiguous_sinks" if candidates else "compatible_path_missing"
                            ],
                        }
                    )
                )
                continue
            result = candidates[0]
            choices = [
                (e, endpoint_paths(source, result, e))
                for e in configuration.endpoints
                if e.capability == key
            ]
            choices = [(e, ids) for e, ids in choices if ids]
            if len(choices) != 1:
                entries.append(
                    entry_record(
                        {
                            **base,
                            "reasons": ["endpoint_configuration_missing_or_ambiguous"],
                            "result_id": result.id,
                            "path_ids": tuple(p.path.id for p in result.paths),
                        }
                    )
                )
                continue
            endpoint, path_ids = choices[0]
            entries.append(
                entry_record(
                    {
                        **base,
                        "status": "draft",
                        "result_id": result.id,
                        "path_ids": path_ids,
                        "endpoint": endpoint,
                    }
                )
            )
    return Plans(
        scan_sha256=digest(raw),
        source_fingerprint=selected.source_fingerprint,
        configuration_sha256=digest(configuration_raw) if configuration_raw else None,
        investigations={k: digest(v[0]) for k, v in reports.items()},
        scanner_source_state="controlled_snapshot" if controlled else "unverified",
        entries=tuple(entries),
    )
