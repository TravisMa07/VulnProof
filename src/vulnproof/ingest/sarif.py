"""Bounded, offline importer for the documented Semgrep SARIF 2.1.0 subset."""

import hashlib
import json
import re
from typing import cast
from urllib.parse import unquote, urlsplit

from vulnproof.models import (
    Finding,
    Reason,
    SourceBinding,
    SourceLocation,
    SourceSnapshot,
    ToolIdentity,
)
from vulnproof.models.common import relative_path

from .models import Diagnostic, ImportedFinding, ImportedRun, IngestionDocument

MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_RESULTS = 10_000
MAX_RUNS = 128
MAX_RULES = 10_000
_SCANNERS = {"semgrep", "semgrep oss", "semgrep ce", "semgrep pro"}
_CWE = re.compile(r"^(CWE-[1-9][0-9]*)(?::.*)?$")


class ImportFailure(ValueError):
    """An unusable document; no partial output should be published."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("expected an object")
    return cast(dict[str, object], value)


def _array(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValueError("expected an array")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("expected nonempty text")
    return value


def _index(value: object, length: int) -> int:
    if type(value) is not int or not 0 <= value < length:
        raise ValueError("invalid array index")
    return value


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _constant(value: str) -> object:
    raise ValueError("non-finite JSON number")


def decode_sarif(data: bytes) -> tuple[str, dict[str, object]]:
    if len(data) > MAX_INPUT_BYTES:
        raise ImportFailure("input_too_large", "SARIF exceeds the 10 MiB input limit")
    try:
        text = data.decode("utf-8")
        # Bound nesting before invoking the recursive JSON parser, respecting strings.
        depth, quoted, escaped = 0, False, False
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
                if depth > MAX_JSON_DEPTH:
                    raise ValueError("JSON nesting exceeds 64 levels")
            elif char in "]}":
                depth -= 1
        doc = _object(json.loads(text, object_pairs_hook=_unique_keys, parse_constant=_constant))
        # Escaped lone surrogates and overflowed JSON floats are not portable evidence.
        json.dumps(doc, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ImportFailure("invalid_json", "Expected unambiguous, bounded UTF-8 JSON") from exc
    if doc.get("version") != "2.1.0" or not isinstance(doc.get("runs"), list):
        raise ImportFailure("unsupported_document", "Expected SARIF 2.1.0 with a runs array")
    if len(_array(doc["runs"])) > MAX_RUNS:
        raise ImportFailure("too_many_runs", "SARIF exceeds the 128 run limit")
    return text, doc


def repository_uri(artifact: dict[str, object]) -> str:
    if artifact.get("uriBaseId") not in (None, "%SRCROOT%"):
        raise ValueError("unsupported URI base")
    uri = _text(artifact.get("uri"))
    if "?" in uri or "#" in uri:
        raise ValueError("source URI has query or fragment delimiters")
    if re.search(r"%(?![0-9a-fA-F]{2})", uri):
        raise ValueError("invalid URI encoding")
    parts = urlsplit(uri)
    if parts.scheme or parts.netloc or parts.query or parts.fragment:
        raise ValueError("expected a relative source URI")
    path = unquote(uri, errors="strict")
    if "%" in path or any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise ValueError("ambiguous encoding or control character in source URI")
    return relative_path(path)


def _location(result: dict[str, object]) -> SourceLocation:
    locations = _array(result.get("locations"))
    if not locations:
        raise ValueError("missing primary location")
    physical = _object(_object(locations[0]).get("physicalLocation"))
    artifact = _object(physical.get("artifactLocation"))
    if "index" in artifact:
        raise ValueError("artifact-table references are unsupported")
    # %SRCROOT% is treated as a logical root, never resolved to a host directory.
    path = repository_uri(artifact)
    region = _object(physical.get("region"))
    return SourceLocation.model_validate(
        {
            "path": path,
            "start_line": region.get("startLine"),
            "end_line": region.get("endLine"),
            "start_column": region.get("startColumn"),
            "end_column": region.get("endColumn"),
        }
    )


def _rule(
    result: dict[str, object], rules: list[object], by_id: dict[str, list[dict[str, object]]]
) -> tuple[str, dict[str, object]]:
    reference = _object(result.get("rule", {}))
    if reference.get("toolComponent") is not None:
        raise ValueError("extension rule references are unsupported")
    ids = [result[key] for key in ("ruleId",) if key in result]
    if "id" in reference:
        ids.append(reference["id"])
    indexes = [result["ruleIndex"]] if "ruleIndex" in result else []
    if "index" in reference:
        indexes.append(reference["index"])
    descriptor: dict[str, object] = {}
    for value in indexes:
        candidate = _object(rules[_index(value, len(rules))])
        ids.append(candidate.get("id"))
        descriptor = candidate
    rule_id = _text(ids[0]) if ids else ""
    if not rule_id or any(_text(item) != rule_id for item in ids):
        raise ValueError("missing or conflicting rule references")
    candidates = by_id.get(rule_id, [])
    if len(candidates) > 1:
        raise ValueError("ambiguous duplicate rule descriptors")
    if candidates:
        descriptor = candidates[0]
    return rule_id, descriptor


def _cwes(descriptor: dict[str, object]) -> tuple[str, ...]:
    properties = _object(descriptor.get("properties", {}))
    tags = _array(properties.get("tags", []))
    cwes: set[str] = set()
    for tag in tags:
        match = _CWE.fullmatch(_text(tag))
        if match:
            cwes.add(match[1])
    return tuple(sorted(cwes))


def _scan_status(run: dict[str, object]) -> str:
    invocations = _array(run.get("invocations", []))
    successful = bool(invocations)
    problems = False
    for value in invocations:
        invocation = _object(value)
        state = invocation.get("executionSuccessful")
        if state is not None and type(state) is not bool:
            raise ValueError("invalid executionSuccessful")
        successful = successful and state is True
        problems = problems or state is False
        for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
            for item in _array(invocation.get(key, [])):
                notification = _object(item)
                # SARIF notifications default to warning when the level is omitted.
                if notification.get("level", "warning") != "none":
                    problems = True
    if problems:
        return "reported_problems"
    return "reported_success" if successful else "unknown"


def ingest_sarif(data: bytes) -> IngestionDocument:
    """Normalize observations from bytes. Never access source files or external references."""
    text, doc = decode_sarif(data)
    digest = hashlib.sha256(data).hexdigest()
    findings: list[ImportedFinding] = []
    runs: list[ImportedRun] = []
    snapshots: list[SourceSnapshot] = []
    diagnostics: list[Diagnostic] = []
    count = 0

    def diagnose(code: str, pointer: str, message: str, *, error: bool = True) -> None:
        diagnostics.append(
            Diagnostic(
                code=code,
                severity="error" if error else "warning",
                pointer=pointer,
                message=message,
            )
        )

    for run_index, raw_run in enumerate(_array(doc["runs"])):
        pointer = f"/runs/{run_index}"
        scanner: ToolIdentity | None = None
        results: list[object] | None = None
        try:
            run = _object(raw_run)
            results = _array(run.get("results", []))
            count += len(results)
            if count > MAX_RESULTS:
                raise ImportFailure("too_many_results", "SARIF exceeds the 10,000 result limit")
            driver = _object(_object(run.get("tool")).get("driver"))
            name = _text(driver.get("name"))
            version = driver.get("semanticVersion", driver.get("version"))
            scanner = ToolIdentity(name=name, version=None if version is None else _text(version))
            if name.casefold() not in _SCANNERS:
                raise ValueError("only Semgrep driver names are supported")
            if "externalPropertyFileReferences" in run:
                raise ValueError("external property files are unsupported")
            rules = _array(driver.get("rules", []))
            if len(rules) > MAX_RULES:
                raise ValueError("run exceeds the 10,000 rule limit")
            by_id: dict[str, list[dict[str, object]]] = {}
            for raw_rule in rules:
                descriptor = _object(raw_rule)
                by_id.setdefault(_text(descriptor.get("id")), []).append(descriptor)
        except ImportFailure:
            raise
        except ValueError:
            diagnose(
                "unsupported_run", pointer, "Run has invalid metadata or unsupported structure"
            )
            runs.append(
                ImportedRun(
                    run_index=run_index,
                    scanner=scanner,
                    supported=False,
                    result_count=None if results is None else len(results),
                    rejected_count=0 if results is None else len(results),
                )
            )
            continue
        try:
            scan_status = _scan_status(run)
        except ValueError:
            scan_status = "unknown"
            diagnose("invalid_scan_metadata", pointer + "/invocations", "Invalid scan metadata")
        if scan_status == "reported_problems":
            diagnose(
                "scanner_reported_problems",
                pointer + "/invocations",
                "Scanner reported an unsuccessful invocation or notification",
            )
        elif scan_status == "unknown":
            diagnose(
                "scan_status_unknown",
                pointer + "/invocations",
                "Scan completion is unknown",
                error=False,
            )
        snapshot_id = f"source:{digest}:r{run_index}"
        snapshots.append(SourceSnapshot(id=snapshot_id))
        imported = 0
        seen: dict[str, str] = {}
        assert results is not None
        for result_index, raw_result in enumerate(results):
            ref = f"{pointer}/results/{result_index}"
            code, context = "invalid_result", "result or message"
            try:
                result = _object(raw_result)
                message = _object(result.get("message"))
                _text(message.get("text", message.get("markdown")))
                code, context = "invalid_rule_reference", "rule reference"
                rule_id, descriptor = _rule(result, rules, by_id)
                code, context = "invalid_location", "primary source location"
                location = _location(result)
                code, context = "invalid_cwe_metadata", "rule CWE metadata"
                cwes = _cwes(descriptor)
                code, context = "invalid_result_metadata", "suppression or level metadata"
                suppression = _array(result.get("suppressions", []))
                for item in suppression:
                    _object(item)
                level = result.get("level")
                finding = Finding(
                    id=f"finding:{digest}:r{run_index}:n{result_index}",
                    scanner=scanner,
                    rule_id=rule_id,
                    original_ref="#" + ref,
                    cwes=cwes,
                    location=location,
                    source=SourceBinding(
                        expected_snapshot_id=snapshot_id,
                        reason=Reason(
                            code="source_not_verified", message="Source content not inspected"
                        ),
                    ),
                )
                # Exact structural duplicates within a run only. No fingerprint-based merging.
                key = hashlib.sha256(
                    json.dumps(
                        result, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                    ).encode()
                ).hexdigest()
                record = ImportedFinding.model_validate(
                    {
                        "finding": finding,
                        "run_index": run_index,
                        "result_index": result_index,
                        "duplicate_of": seen.get(key),
                        "suppression": "present" if suppression else "absent",
                        "level": level,
                    }
                )
                findings.append(record)
                imported += 1
                seen.setdefault(key, finding.id)
                if record.duplicate_of:
                    diagnose("duplicate_result", ref, "Exact duplicate retained", error=False)
                if not cwes:
                    diagnose("cwe_unknown", ref, "No recognized explicit CWE tag", error=False)
                if suppression:
                    diagnose("suppressed_result", ref, "Scanner suppression retained", error=False)
                if len(_array(result["locations"])) > 1:
                    diagnose(
                        "additional_locations",
                        ref,
                        "Only the first location was normalized",
                        error=False,
                    )
            except ValueError:
                diagnose(code, ref, f"Invalid or unsupported {context}; original result retained")
        runs.append(
            ImportedRun.model_validate(
                {
                    "run_index": run_index,
                    "scanner": scanner,
                    "supported": True,
                    "result_count": len(results),
                    "imported_count": imported,
                    "rejected_count": len(results) - imported,
                    "scan_status": scan_status,
                }
            )
        )
    return IngestionDocument(
        schema_version="1.0",
        input_sha256=digest,
        input_size_bytes=len(data),
        raw_sarif=text,
        runs=tuple(runs),
        snapshots=tuple(snapshots),
        findings=tuple(findings),
        diagnostics=tuple(diagnostics),
        result_count=count,
        status="partial" if any(item.severity == "error" for item in diagnostics) else "complete",
    )
