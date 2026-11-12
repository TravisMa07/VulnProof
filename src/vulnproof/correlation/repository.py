"""Account for repository SARIF occurrences using retained static evidence."""

import hashlib
import io
import json
import tokenize
from collections import Counter, defaultdict
from dataclasses import asdict
from importlib.resources import files
from pathlib import Path

from vulnproof.artifacts import read_local
from vulnproof.intake import Inventory, Location, inventory, obj
from vulnproof.investigation.capabilities import ROUTE_RULE as ROUTE_RULE
from vulnproof.investigation.capabilities import RULE as RULE
from vulnproof.investigation.capabilities import SERVING_RULES, mapping_for
from vulnproof.models import SourceLocation
from vulnproof.provenance.filesystem import open_root, scan_tree
from vulnproof.provenance.models import MAX_FILE_BYTES, fingerprint
from vulnproof.scanning.repository import capture_repository
from vulnproof.static.models import (
    CODEQL_VERSION,
    MAX_LOG_BYTES,
    MAX_SARIF_BYTES,
    PACK_VERSION,
    QUERY_SHA256,
    QueryResult,
)
from vulnproof.static.repository import Investigation, ScanInput
from vulnproof.static.sarif import normalize_sarif

from .engine import MAX_CANDIDATES, MAX_DOCUMENT_BYTES, CorrelationFailure, _artifact
from .file_reads import arguments, overlaps, same_argument, serving_arguments


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def document(value: object) -> str:
    content = json.dumps(value, indent=2) + "\n"
    if len(content.encode()) > MAX_DOCUMENT_BYTES:
        raise ValueError("Document exceeds size limit")
    return content


def snapshot_inventory(raw: bytes, root: Path, component: str | None) -> Inventory:
    # Captures have no Git identity; avoid spawning Git only to discard its result.
    return inventory(raw, root, component, inspect_git=False)


def prepare_inventory(repo: Path, component: str | None, path: Path, output: Path) -> None:
    try:
        previous = json.loads(read_local(path.absolute().parent, path.name, MAX_DOCUMENT_BYTES))
        if not isinstance(previous, dict) or not isinstance(previous.get("raw_sarif"), str):
            raise ValueError("Missing embedded SARIF")
        scope = previous.get("component")
        if (
            scope is not None
            and not isinstance(scope, str)
            or component is not None
            and component != scope
        ):
            raise ValueError("Incompatible component")
        previous["checkout_head"] = None
        prepare_import(repo, scope, previous["raw_sarif"].encode(), output, previous)
    except (ValueError, RecursionError) as exc:
        raise CorrelationFailure(
            "invalid_inventory", "Inventory must agree with the captured files and embedded SARIF"
        ) from exc


def prepare_import(
    repo: Path,
    component: str | None,
    raw: bytes,
    output: Path,
    previous: dict[str, object] | None = None,
) -> None:
    manifest, exclusions = capture_repository(repo, component, output)
    inv = snapshot_inventory(raw, output / "snapshot", component)
    if previous is not None and asdict(inv) != previous:
        raise CorrelationFailure(
            "inventory_mismatch", "Captured files or imported inventory changed since intake"
        )
    (output / "diagnostics").mkdir()
    (output / "diagnostics/raw.sarif").write_bytes(raw)
    try:
        (output / "inventory.json").write_text(document(asdict(inv)), encoding="utf-8")
    except ValueError as exc:
        raise CorrelationFailure("inventory_limit", "Inventory exceeds size limit") from exc
    receipt = {
        "schema_version": "1.0",
        "profile": "repository-import-v1",
        "outcome": "completed" if inv.status == "complete" else "partial",
        "component": component,
        "files": [f.model_dump() for f in manifest],
        "excluded_paths": exclusions,
        "source_fingerprint": fingerprint(manifest),
        "sarif_sha256": inv.input_sha256,
        "result_count": inv.result_count,
    }
    (output / "scan.json").write_text(document(receipt), encoding="utf-8")


def region(loc: Location, raw: object) -> SourceLocation | None:
    if loc.state != "present" or not loc.path or not loc.start_line:
        return None
    position = obj(obj(obj(raw).get("physicalLocation")).get("region"))
    try:
        return SourceLocation.model_validate(
            dict(
                path=loc.path,
                start_line=loc.start_line,
                end_line=loc.end_line,
                start_column=position.get("startColumn"),
                end_column=position.get("endColumn"),
            )
        )
    except ValueError:
        return None


class ColumnUnits:
    """Translate SARIF UTF-16 offsets to the code-point offsets used by Python tokens."""

    def __init__(self, source: Path) -> None:
        self.source = source
        self.lines: dict[str, list[str] | None] = {}

    def normalize(self, location: SourceLocation, kind: object) -> SourceLocation | None:
        if kind == "unicodeCodePoints" or not (location.start_column or location.end_column):
            return location
        if kind != "utf16CodeUnits":
            return None
        if location.path not in self.lines:
            data = read_local(self.source, location.path, MAX_FILE_BYTES)
            try:
                encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
                text = data.decode(encoding)
            except SyntaxError, UnicodeError, LookupError:
                return None
            self.lines[location.path] = (
                text.splitlines() if any(ord(c) > 0xFFFF for c in text) else None
            )
        lines = self.lines[location.path]
        if lines is None:
            return location
        columns: dict[str, int] = {}
        for field, number, column in (
            ("start_column", location.start_line, location.start_column),
            ("end_column", location.end_line or location.start_line, location.end_column),
        ):
            if column is None:
                continue
            if number > len(lines):
                return None
            units = lines[number - 1].encode("utf-16-le")
            offset = (column - 1) * 2
            if offset > len(units):
                return None
            try:
                columns[field] = len(units[:offset].decode("utf-16-le")) + 1
            except UnicodeDecodeError:
                return None
        return location.model_copy(update=columns)


def correlate_repository(scan: Path, investigation: Path) -> str:
    try:
        return _correlate(scan.absolute(), investigation.absolute())
    except (ValueError, OSError, RecursionError) as exc:
        raise CorrelationFailure(
            "invalid_repository_evidence",
            "Repository inputs are inconsistent, unreadable, or exceed correlation limits",
        ) from exc


def _correlate(scan: Path, analysis: Path) -> str:
    receipt = read_local(scan, "scan.json", MAX_DOCUMENT_BYTES)
    selected = ScanInput.model_validate_json(receipt)
    metadata = json.loads(receipt)
    controlled = selected.profile == "repository-scan-v1"
    if controlled and metadata.get("rules_sha256") not in {
        "ab7be84091543e7f00b97d73eff516bded34e9e9d11b68841773c7adcf890fb3",
        "cab7dcca13bd527100a33253930c86654f0dee9e37f938f7a384258d2bf9dd12",
        digest(files("vulnproof.scanning").joinpath("repository.yaml").read_bytes()),
    }:
        raise ValueError("Unknown controlled ruleset")
    source = scan / "snapshot"
    with open_root(source) as fd:
        tree = scan_tree(fd)
    if (
        tree.files != selected.files
        or tree.excluded_paths
        or fingerprint(tree.files) != selected.source_fingerprint
    ):
        raise ValueError("Source manifest mismatch")
    raw = read_local(scan, "diagnostics/raw.sarif", MAX_SARIF_BYTES)
    inv = snapshot_inventory(raw, source, selected.component)
    saved = read_local(scan, "inventory.json", MAX_DOCUMENT_BYTES)
    if inv.input_sha256 != metadata.get("sarif_sha256") or json.loads(saved) != json.loads(
        document(asdict(inv))
    ):
        raise ValueError("Scanner evidence mismatch")
    data = read_local(analysis, "investigation.json", MAX_DOCUMENT_BYTES)
    report = Investigation.model_validate_json(data)
    if (
        report.scan_sha256 != digest(receipt)
        or report.source_fingerprint != selected.source_fingerprint
        or report.component != selected.component
        or report.query_sha256 != QUERY_SHA256
    ):
        raise ValueError("Investigation does not match selected scan and query")
    if report.outcome in ("completed", "partial") and (
        not report.tool
        or report.tool.name != "CodeQL"
        or report.tool.version != CODEQL_VERSION
        or report.tool.rule_pack != "codeql/python-queries@" + PACK_VERSION
    ):
        raise ValueError("Unexpected CodeQL tool or query pack")
    for command in report.commands:
        _artifact(analysis, command.log, MAX_LOG_BYTES)
    codeql = _artifact(analysis, report.raw_sarif, MAX_SARIF_BYTES) if report.raw_sarif else None
    by_path: dict[str, list[QueryResult]] = defaultdict(list)
    if report.outcome in ("completed", "partial"):
        if (
            not codeql
            or not report.raw_sarif
            or report.raw_sarif.truncated
            or [c.stage for c in report.commands] != ["version", "extract", "query"]
            or any(c.return_code != 0 or c.outcome != "completed" for c in report.commands)
        ):
            raise ValueError("Incomplete CodeQL evidence")
        root = analysis / "work/source"
        with open_root(root) as fd:
            copied = scan_tree(fd)
        if copied.files != tree.files or copied.excluded_paths:
            raise ValueError("CodeQL source copy mismatch")
        results, notes = normalize_sarif(codeql, root, tree.files)
        if any(
            r.get("columnKind", "utf16CodeUnits") != "unicodeCodePoints"
            for r in json.loads(codeql)["runs"]
        ):
            raise ValueError("Unexpected column units for pinned CodeQL report")
        partial = bool(notes or any(r.diagnostics for r in results))
        if (
            results != report.results
            or notes != report.diagnostics
            or partial != (report.outcome == "partial")
        ):
            raise ValueError("CodeQL evidence mismatch")
        for result in results:
            if result.sink and result.paths:
                by_path[result.sink.path].append(result)
    elif report.results:
        raise ValueError("Unsuccessful investigation contains results")
    raw_runs = json.loads(inv.raw_sarif)["runs"]
    entries = []
    comparisons = 0
    counts: Counter[str] = Counter()
    links = 0
    operations: dict[tuple[str, str], list[SourceLocation]] = {}
    units = ColumnUnits(source)
    for run in inv.runs:
        for index, entry in enumerate(run.entries):
            item = obj(raw_runs[run.index]["results"][index])
            raw_locations = item.get("locations", [])
            regions = []
            for loc, raw_location in zip(
                entry.locations,
                raw_locations if isinstance(raw_locations, list) else [],
                strict=False,
            ):
                position = region(loc, raw_location)
                if position and position.path.endswith(".py"):
                    kind = raw_runs[run.index].get("columnKind", "utf16CodeUnits")
                    position = units.normalize(position, kind)
                if position:
                    regions.append(position)
            candidates: dict[str, list[str]] = {}
            mapping = mapping_for(run.scanner, entry.rule_id)
            if mapping is None:
                status = "unsupported_mapping"
            elif not regions:
                status = "location_unavailable"
            elif report.outcome in ("unsupported", "failed"):
                status = "analysis_" + report.outcome
            else:
                matching_operations: set[SourceLocation] = set()
                for location in regions:
                    family = mapping.sink_family
                    operation_key = (location.path, family)
                    if operation_key not in operations:
                        operations[operation_key] = (
                            arguments(source, location.path)
                            if family == "open"
                            else serving_arguments(source, location.path, family)
                        )
                    comparisons += len(operations[operation_key]) * (
                        1 + len(by_path.get(location.path, []))
                    )
                    if comparisons > 1_000_000:
                        raise ValueError("Correlation comparison limit exceeded")
                    compatible = [
                        arg for arg in operations[operation_key] if overlaps(arg, location)
                    ]
                    matching_operations.update(compatible)
                    for candidate in by_path.get(location.path, []):
                        if (
                            candidate.sink
                            and overlaps(location, candidate.sink)
                            and any(same_argument(arg, candidate.sink) for arg in compatible)
                        ):
                            candidates[candidate.id] = [p.path.id for p in candidate.paths]
                status = "no_candidate"
                if candidates:
                    status = (
                        "single_candidate"
                        if len(candidates) == len(matching_operations) == 1
                        else "ambiguous"
                    )
            counts[status] += 1
            links += sum(len(paths) for paths in candidates.values())
            if links > MAX_CANDIDATES:
                raise ValueError("Candidate output limit exceeded")
            entries.append(
                {
                    "finding": asdict(entry),
                    "producer": run.scanner,
                    **(
                        {"sink_family": mapping.sink_family}
                        if mapping is not None and entry.rule_id in SERVING_RULES
                        else {}
                    ),
                    "run": run.index,
                    "regions": [r.model_dump() for r in regions],
                    "location_precision": "columns"
                    if regions and all(r.start_column and r.end_column for r in regions)
                    else "limited",
                    "status": status,
                    "candidates": candidates,
                    "declared_revisions": run.declared_revisions,
                }
            )
    with open_root(source) as fd:
        after = scan_tree(fd)
    if (
        after.files != tree.files
        or after.excluded_paths
        or read_local(scan, "scan.json", MAX_DOCUMENT_BYTES) != receipt
        or read_local(analysis, "investigation.json", MAX_DOCUMENT_BYTES) != data
    ):
        raise ValueError("Evidence changed during correlation")
    return document(
        {
            "python_region_column_kind": "unicodeCodePoints",
            "schema_version": "1.0",
            "policy": "repository-file-read-v1",
            "query_id": report.query_id,
            "source_fingerprint": selected.source_fingerprint,
            "scan_sha256": report.scan_sha256,
            "investigation_sha256": digest(data),
            "inventory_sha256": digest(saved),
            "sarif_sha256": inv.input_sha256,
            "codeql_sarif_sha256": digest(codeql) if codeql else None,
            "scanner_source_state": "controlled_snapshot" if controlled else "unverified",
            "scan_outcome": selected.outcome,
            "inventory_status": inv.status,
            "runs": [
                {
                    "index": run.index,
                    "producer": run.scanner,
                    "version": run.version,
                    "issues": run.issues,
                    "result_count": run.result_count,
                }
                for run in inv.runs
            ],
            "analysis_outcome": report.outcome,
            "analysis_diagnostics": [n.model_dump() for n in report.diagnostics],
            "counts": counts,
            "findings": entries,
        }
    )
