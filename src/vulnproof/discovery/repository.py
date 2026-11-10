"""Discover request bindings for verified repository path evidence."""

import json
from pathlib import Path

from vulnproof.artifacts import read_local
from vulnproof.correlation.engine import MAX_DOCUMENT_BYTES, CorrelationFailure
from vulnproof.correlation.repository import correlate_repository, digest, document
from vulnproof.models import SourceLocation, StaticPath
from vulnproof.provenance.models import MAX_FILE_BYTES
from vulnproof.static.repository import Investigation, ScanInput

from .flask import Handler, Module, parse_module


def same_span(a: SourceLocation, b: SourceLocation) -> bool:
    return (a.path, a.start_line, a.end_line or a.start_line, a.start_column, a.end_column) == (
        b.path,
        b.start_line,
        b.end_line or b.start_line,
        b.start_column,
        b.end_column,
    )


def binding(handler: Handler, nodes: list[SourceLocation]) -> dict[str, object] | None:
    local_nodes = [
        n
        for n in nodes
        if handler.location.start_line
        <= n.start_line
        <= (n.end_line or n.start_line)
        <= (handler.location.end_line or handler.location.start_line)
        and not any(start <= n.start_line <= end for start, end in handler.nested_scopes)
    ]
    if not local_nodes:
        return None
    matched = [
        (key, loc) for key, loc in handler.inputs if any(same_span(loc, n) for n in local_nodes)
    ]
    reasons = list(handler.gaps)
    if len(matched) != 1:
        reasons.append(
            "query_parameter_unresolved" if not matched else "ambiguous_query_parameters"
        )
    return {
        "handler": handler.name,
        "handler_location": handler.location.model_dump(),
        "application_symbol": handler.application,
        "application_location": handler.declaration.model_dump() if handler.declaration else None,
        "routes": [
            {"method": r.method, "path": r.path, "evidence": r.evidence.model_dump()}
            for r in handler.routes
        ],
        "inputs": [
            {"kind": "query", "name": key, "location": loc.model_dump()} for key, loc in matched
        ],
        "gaps": reasons,
    }


def discover(
    scan: Path,
    investigation: Path,
    correlation: Path,
    *,
    route_parts: dict[tuple[str, int], dict[str, object]] | None = None,
) -> str:
    try:
        supplied = read_local(correlation.absolute().parent, correlation.name, MAX_DOCUMENT_BYTES)
        report = json.loads(correlate_repository(scan, investigation))
        if json.loads(supplied) != report:
            raise ValueError("Correlation changed")
        data = read_local(investigation, "investigation.json", MAX_DOCUMENT_BYTES)
        receipt = read_local(scan, "scan.json", MAX_DOCUMENT_BYTES)
        if (
            digest(data) != report["investigation_sha256"]
            or digest(receipt) != report["scan_sha256"]
        ):
            raise ValueError("Investigation changed")
        selected = ScanInput.model_validate_json(receipt)
        manifest = {f.path: f.sha256 for f in selected.files}
        modules: dict[str, Module] = {}

        def inspect(path: StaticPath) -> dict[str, object]:
            bindings: list[dict[str, object]] = []
            gaps = set()
            # CodeQL may start at the imported Flask request object. The first
            # subsequent source node anchors the handler; later handlers can be callees.
            for anchor in path.locations:
                filename = anchor.path
                if not filename.endswith(".py"):
                    break
                if filename not in modules:
                    raw = read_local(scan / "snapshot", filename, MAX_FILE_BYTES)
                    if digest(raw) != manifest[filename]:
                        raise ValueError("Source changed")
                    modules[filename] = parse_module(filename, raw)
                module = modules[filename]
                if module.issue:
                    gaps.add(module.issue)
                    break
                if anchor.start_line in module.request_import_lines:
                    continue
                nodes = [n for n in path.locations if n.path == filename]
                for handler in module.handlers:
                    if (
                        not handler.location.start_line
                        <= anchor.start_line
                        <= (handler.location.end_line or handler.location.start_line)
                    ):
                        continue
                    if any(
                        start <= anchor.start_line <= end for start, end in handler.nested_scopes
                    ):
                        continue
                    observed = binding(handler, nodes)
                    if observed is not None:
                        if route_parts is not None:
                            route_parts[path.id, len(bindings)] = {
                                "route": handler.route_literal,
                                "methods": [m.upper() for m in handler.methods],
                                "location": handler.decorator.model_dump(),
                            }
                        bindings.append(observed)
                break
            if not bindings:
                gaps.add("handler_unresolved")
                if selected.component:
                    gaps.add("registration_may_be_outside_component")
            if len(bindings) > 1:
                gaps.add("multiple_route_bindings")
            return {"bindings": bindings, "gaps": sorted(gaps)}

        paths = {
            p.path.id: p.path
            for r in Investigation.model_validate_json(data).results
            for p in r.paths
        }
        observations = {}
        findings = []
        for row in report["findings"]:
            ids = [pid for values in row["candidates"].values() for pid in values]
            for pid in ids:
                if pid not in observations:
                    observations[pid] = inspect(paths[pid])
            findings.append(
                {
                    "finding_id": row["finding"]["id"],
                    "correlation_status": row["status"],
                    "candidates": row["candidates"],
                }
            )
        return document(
            {
                "schema_version": "1.0",
                "adapter": "flask-direct-v1",
                "source_fingerprint": selected.source_fingerprint,
                "component": selected.component,
                "scanner_source_state": report["scanner_source_state"],
                "analysis_outcome": report["analysis_outcome"],
                "correlation_sha256": digest(supplied),
                "paths": observations,
                "findings": findings,
            }
        )
    except (OSError, ValueError, KeyError, RecursionError) as exc:
        raise CorrelationFailure(
            "invalid_discovery_evidence",
            "Discovery requires consistent repository scan, investigation and correlation evidence",
        ) from exc
