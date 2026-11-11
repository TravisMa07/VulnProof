"""Account for each SARIF occurrence and inspect referenced checkout files on demand."""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .artifacts import read_local
from .ingest.sarif import MAX_RESULTS, MAX_RULES, ImportFailure, decode_sarif, repository_uri
from .models.common import relative_path
from .provenance.filesystem import excluded, open_root
from .provenance.git import checkout_head
from .provenance.models import MAX_FILE_BYTES, MAX_TOTAL_BYTES

MAX_LOCATIONS = 50_000


@dataclass
class Location:
    state: str
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    sha256: str | None = None


@dataclass
class Occurrence:
    id: str
    original_ref: str
    rule_id: str | None = None
    message: str | None = None
    level: str | None = None
    suppressed: bool = False
    duplicate_of: str | None = None
    locations: list[Location] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)


@dataclass
class Run:
    index: int
    scanner: str | None
    version: str | None
    declared_revisions: list[str]
    result_count: int | None
    entries: list[Occurrence] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)


@dataclass
class Inventory:
    input_sha256: str
    raw_sarif: str
    checkout_head: str | None
    runs: list[Run]
    result_count: int
    status: Literal["complete", "partial"]
    schema_version: Literal["1.0"] = "1.0"
    component: str | None = None
    profile: Literal["repository-intake"] = "repository-intake"
    scanner_source_state: Literal["unverified"] = "unverified"


def obj(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def indexed(items: object, index: object) -> dict[str, object]:
    if not isinstance(items, list) or type(index) is not int or not 0 <= index < len(items):
        raise ValueError("invalid index")
    return obj(items[index])


def resolve_rule(result: dict[str, object], rules: object) -> str | None:
    ref = obj(result.get("rule"))
    if "toolComponent" in ref or ("rule" in result and not isinstance(result["rule"], dict)):
        raise ValueError("unsupported rule reference")
    ids = [record[key] for record, key in ((result, "ruleId"), (ref, "id")) if key in record]
    for record, key in ((result, "ruleIndex"), (ref, "index")):
        if key in record:
            ids.append(indexed(rules, record[key]).get("id"))
    if not ids or not string(ids[0]) or any(i != ids[0] for i in ids):
        raise ValueError("missing or conflicting rule identity")
    identity = string(ids[0])
    if identity and len(identity) > 4096:
        raise ValueError("rule identity too long")
    return identity


class Checkout:
    def __init__(self, root: Path, component: str | None):
        self.component = component
        self.root = root
        self.remaining = MAX_TOTAL_BYTES
        self.cache: dict[str, tuple[str, str | None, int]] = {}

    def inspect(self, path: str) -> tuple[str, str | None, int]:
        if path in self.cache:
            return self.cache[path]
        state, digest, lines = "present", None, 0
        bound = min(self.remaining, MAX_FILE_BYTES)
        if self.component and path != self.component and not path.startswith(self.component + "/"):
            state = "outside_component"
        elif excluded(path):
            state = "excluded"
        elif bound == 0:
            state = "read_limit"
        else:
            try:
                data = read_local(self.root, path, bound)
                self.remaining -= len(data)
                digest = hashlib.sha256(data).hexdigest()
                lines = (
                    data.count(b"\n")
                    + data.count(b"\r")
                    - data.count(b"\r\n")
                    + int(bool(data) and not data.endswith((b"\n", b"\r")))
                )
            except FileNotFoundError:
                state = "missing_file"
            except OSError:
                state = "unreadable_file"
            except ValueError as exc:
                if str(exc) == "artifact exceeds limit":
                    self.remaining -= bound
                    state = "read_limit"
                else:
                    state = "unreadable_file"
        self.cache[path] = state, digest, lines
        return self.cache[path]

    def locate(self, raw: object, artifacts: object) -> Location:
        physical = obj(obj(raw).get("physicalLocation"))
        ref = obj(physical.get("artifactLocation"))
        if not ref:
            return Location("missing_physical_location")
        if "index" in ref:
            try:
                table = obj(indexed(artifacts, ref["index"]).get("location"))
            except ValueError:
                return Location("invalid_artifact_index")
            if not table or any(
                k in table and k in ref and table[k] != ref[k]
                for k in ("uri", "uriBaseId", "index")
            ):
                return Location("conflicting_artifact_reference")
            ref = table | ref
        uri = ref.get("uri")
        if not isinstance(uri, str) or len(uri) > 4096:
            return Location("unsupported_or_unsafe_uri")
        try:
            path = repository_uri(ref)
        except ValueError:
            return Location("unsupported_or_unsafe_uri")
        region = obj(physical.get("region"))
        start, end = region.get("startLine"), region.get("endLine")
        if (
            ("region" in physical and not isinstance(physical["region"], dict))
            or (start is not None and (type(start) is not int or start < 1))
            or (end is not None and (type(end) is not int or type(start) is not int or end < start))
        ):
            return Location("invalid_region", path)
        state, digest, count = self.inspect(path)
        if (
            state == "present"
            and isinstance(start, int)
            and (start > count or (isinstance(end, int) and end > count))
        ):
            state = "line_out_of_range"
        return Location(
            state,
            path,
            start if isinstance(start, int) else None,
            end if isinstance(end, int) else None,
            digest,
        )


def inventory(
    data: bytes, repo: Path, component: str | None = None, *, inspect_git: bool = True
) -> Inventory:
    raw, document = decode_sarif(data)
    with open_root(repo.absolute()):
        pass
    if component is not None:
        try:
            relative_path(component)
        except ValueError as exc:
            raise ImportFailure(
                "invalid_component", "Component must be a normalized relative path"
            ) from exc
    checkout = Checkout(repo.absolute(), component)
    digest = hashlib.sha256(data).hexdigest()
    total = location_count = 0
    partial = False
    runs = []
    raw_runs = document["runs"]
    assert isinstance(raw_runs, list)
    for ri, value in enumerate(raw_runs):
        run = obj(value)
        driver = obj(obj(run.get("tool")).get("driver"))
        provenance = run.get("versionControlProvenance", [])
        revisions = (
            [v for p in provenance if (v := string(obj(p).get("revisionId")))]
            if isinstance(provenance, list)
            else []
        )
        results = run.get("results", []) if isinstance(value, dict) else None
        record = Run(
            ri,
            string(driver.get("name")),
            string(driver.get("semanticVersion")) or string(driver.get("version")),
            revisions,
            len(results) if isinstance(results, list) else None,
        )
        runs.append(record)
        if record.scanner is None:
            record.issues.append("missing_producer")
        if "externalPropertyFileReferences" in run:
            record.issues.append("external_properties_unresolved")
        if not isinstance(results, list):
            record.issues.append("unreadable_results")
            partial = True
            continue
        total += len(results)
        if total > MAX_RESULTS:
            raise ImportFailure("too_many_results", "SARIF exceeds the result limit")
        rules = driver.get("rules", [])
        if isinstance(rules, list) and len(rules) > MAX_RULES:
            raise ImportFailure("too_many_rules", "SARIF exceeds the driver rule limit")
        seen: dict[str, str] = {}
        for n, item in enumerate(results):
            row = Occurrence(f"finding:{digest}:r{ri}:n{n}", f"#/runs/{ri}/results/{n}")
            record.entries.append(row)
            signature = hashlib.sha256(
                json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            row.duplicate_of = seen.get(signature)
            seen.setdefault(signature, row.id)
            result = obj(item)
            if not isinstance(item, dict):
                row.issues.append("invalid_result")
                partial = True
                continue
            try:
                row.rule_id = resolve_rule(result, rules)
            except ValueError:
                row.issues.append("unresolved_rule")
            message = obj(result.get("message"))
            row.message = string(message.get("text")) or string(message.get("markdown"))
            if row.message is None:
                row.issues.append("unresolved_message")
            row.level = string(result.get("level"))
            if "level" in result and row.level not in ("none", "note", "warning", "error"):
                row.issues.append("invalid_level")
            suppressions = result.get("suppressions", [])
            if not isinstance(suppressions, list):
                row.issues.append("invalid_suppressions")
            else:
                row.suppressed = bool(suppressions)
            locations = result.get("locations")
            if isinstance(locations, list) and locations:
                location_count += len(locations)
                if location_count > MAX_LOCATIONS:
                    raise ImportFailure("location_limit", "SARIF exceeds the location limit")
                row.locations = [checkout.locate(loc, run.get("artifacts")) for loc in locations]
            else:
                row.issues.append("missing_locations")
            partial |= bool(row.issues) or any(
                loc.state not in ("present", "outside_component") for loc in row.locations
            )
        partial |= bool(record.issues)
    return Inventory(
        digest,
        raw,
        checkout_head(repo.absolute()) if inspect_git else None,
        runs,
        total,
        "partial" if partial else "complete",
        component=component,
    )
