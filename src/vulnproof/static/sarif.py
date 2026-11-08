"""Normalize complete local paths without guessing or splicing missing nodes."""

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import cast
from urllib.parse import unquote, urlsplit

from vulnproof.models import Reason, SourceLocation, StaticPath
from vulnproof.models.common import relative_path
from vulnproof.provenance.models import CapturedFile

from .models import CODEQL_VERSION, MAX_SARIF_BYTES, QUERY_ID, AnalysisPath, QueryResult
from .process import AnalysisFailure


def obj(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("expected an object")
    return cast(dict[str, object], value)


def array(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValueError("expected an array")
    return value


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> object:
    raise ValueError("non-finite JSON constant")


def _decode(data: bytes) -> dict[str, object]:
    if len(data) > MAX_SARIF_BYTES:
        raise ValueError("SARIF limit")
    text = data.decode("utf-8")
    quoted, escaped, depth = False, False, 0
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 64:
                raise ValueError("JSON nesting limit")
        elif char in "]}":
            depth -= 1
    value = obj(json.loads(text, object_pairs_hook=_unique, parse_constant=_constant))
    json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    return value


def _uri(location: dict[str, object], root: Path) -> str:
    value = location.get("uri")
    if not isinstance(value, str) or not value:
        raise ValueError("missing URI")
    if location.get("uriBaseId") not in (None, "%SRCROOT%"):
        raise ValueError("unsupported base")
    if "?" in value or "#" in value or re.search(r"%(?![a-fA-F0-9]{2})", value):
        raise ValueError("ambiguous URI")
    parts = urlsplit(value)
    if parts.scheme not in ("", "file") or parts.netloc:
        raise ValueError("external URI")
    decoded = unquote(parts.path, errors="strict")
    if (
        "%" in decoded
        or ".." in PurePosixPath(decoded).parts
        or any(ord(c) < 32 or ord(c) == 127 for c in decoded)
    ):
        raise ValueError("unsafe source URI")
    path = Path(decoded)
    if path.is_absolute():
        decoded = path.relative_to(root).as_posix()
    elif parts.scheme:
        raise ValueError("relative file URI")
    return relative_path(decoded)


def _location(
    value: object, run: dict[str, object], root: Path, files: dict[str, CapturedFile]
) -> SourceLocation:
    physical = obj(obj(value).get("physicalLocation"))
    artifact = obj(physical.get("artifactLocation"))
    path: str | None = None
    if "index" in artifact:
        index = artifact["index"]
        table = array(run.get("artifacts", []))
        if type(index) is not int or not 0 <= index < len(table):
            raise ValueError("bad artifact index")
        path = _uri(obj(obj(table[index]).get("location")), root)
    if "uri" in artifact:
        direct = _uri(artifact, root)
        if path is not None and direct != path:
            raise ValueError("conflicting artifact locations")
        path = direct
    if path is None or path not in files:
        raise ValueError("location not in captured manifest")
    region = obj(physical.get("region"))
    location = SourceLocation.model_validate(
        {
            "path": path,
            "start_line": region.get("startLine"),
            "end_line": region.get("endLine"),
            "start_column": region.get("startColumn"),
            "end_column": region.get("endColumn"),
        }
    )
    if (location.end_line or location.start_line) > files[path].line_count:
        raise ValueError("location exceeds captured file")
    return location


def _check_rule(result: dict[str, object], driver: dict[str, object]) -> None:
    if result.get("ruleId") != QUERY_ID:
        raise ValueError("unexpected query result")
    reference = obj(result.get("rule", {}))
    if reference.get("id", QUERY_ID) != QUERY_ID or "toolComponent" in reference:
        raise ValueError("conflicting rule reference")
    indexes = [result["ruleIndex"]] if "ruleIndex" in result else []
    if "index" in reference:
        indexes.append(reference["index"])
    for index in indexes:
        rules = array(driver.get("rules", []))
        if type(index) is not int or not 0 <= index < len(rules):
            raise ValueError("invalid rule index")
        if obj(rules[index]).get("id") != QUERY_ID:
            raise ValueError("rule index disagrees with query identity")


def normalize_sarif(
    data: bytes, source_root: Path, files: tuple[CapturedFile, ...]
) -> tuple[tuple[QueryResult, ...], tuple[Reason, ...]]:
    """Return query observations only; no Semgrep lookup or per-finding verdict."""
    try:
        document = _decode(data)
        if document.get("version") != "2.1.0":
            raise ValueError("wrong SARIF version")
        runs = array(document.get("runs"))
        if not runs or len(runs) > 8:
            raise ValueError("invalid run count")
        results: list[QueryResult] = []
        diagnostics: list[Reason] = []
        file_map = {f.path: f for f in files}
        digest = hashlib.sha256(data).hexdigest()
        for run_index, raw_run in enumerate(runs):
            run = obj(raw_run)
            driver = obj(obj(run.get("tool")).get("driver"))
            if driver.get("name") != "CodeQL" or driver.get("semanticVersion") != CODEQL_VERSION:
                raise ValueError("wrong CodeQL producer")
            if "externalPropertyFileReferences" in run:
                raise ValueError("external property files")
            for invocation in array(run.get("invocations", [])):
                item = obj(invocation)
                state = item.get("executionSuccessful")
                if state is not None and (type(state) is not bool or state is False):
                    raise ValueError("unsuccessful analysis invocation")
                for notification in array(item.get("toolExecutionNotifications", [])):
                    if obj(notification).get("level") in ("warning", "error"):
                        diagnostics.append(
                            Reason(
                                code="codeql_notification",
                                message="CodeQL reported an analysis warning or error; see raw SARIF",
                            )
                        )
            for index, raw_result in enumerate(array(run.get("results"))):
                if len(results) >= 1024:
                    raise ValueError("result limit")
                ref = f"/runs/{run_index}/results/{index}"
                notes: list[Reason] = []
                paths: list[AnalysisPath] = []
                observed = 0
                sink: SourceLocation | None = None
                try:
                    result = obj(raw_result)
                    _check_rule(result, driver)
                    sink = _location(array(result.get("locations"))[0], run, source_root, file_map)
                    for flow_index, flow in enumerate(array(result.get("codeFlows", []))):
                        for thread_index, thread in enumerate(array(obj(flow).get("threadFlows"))):
                            observed += 1
                            if observed > 16:
                                raise ValueError("path limit")
                            path_ref = f"{ref}/codeFlows/{flow_index}/threadFlows/{thread_index}"
                            try:
                                nodes = array(obj(thread).get("locations"))
                                if not 2 <= len(nodes) <= 1024:
                                    raise ValueError("incomplete or oversized path")
                                locations = tuple(
                                    _location(obj(n).get("location"), run, source_root, file_map)
                                    for n in nodes
                                )
                                if not locations[-1].overlaps(sink):
                                    raise ValueError("path sink mismatch")
                                paths.append(
                                    AnalysisPath(
                                        original_ref="#" + path_ref,
                                        path=StaticPath(
                                            id=f"path:{digest}:r{run_index}:n{index}:c{flow_index}:t{thread_index}",
                                            locations=locations,
                                        ),
                                    )
                                )
                            except ValueError, IndexError:
                                notes.append(
                                    Reason(
                                        code="path_unavailable",
                                        message="A complete local path could not be normalized; raw nodes retained",
                                    )
                                )
                    if not observed:
                        notes.append(
                            Reason(
                                code="paths_unavailable",
                                message="CodeQL result has no emitted path; this is not evidence of safety",
                            )
                        )
                except ValueError, IndexError:
                    paths = []
                    notes.append(
                        Reason(
                            code="result_unavailable",
                            message="Result structure or source location is unsupported; original result retained",
                        )
                    )
                results.append(
                    QueryResult(
                        id=f"result:{digest}:r{run_index}:n{index}",
                        original_ref="#" + ref,
                        sink=sink,
                        paths=tuple(paths),
                        observed_paths=observed,
                        diagnostics=tuple(notes),
                    )
                )
        return tuple(results), tuple(diagnostics)
    except (ValueError, IndexError, RecursionError) as exc:
        raise AnalysisFailure(
            "invalid_sarif", "CodeQL SARIF is malformed, incompatible, or incomplete"
        ) from exc
