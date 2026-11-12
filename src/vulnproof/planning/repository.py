"""Plan one bounded GET/query test per eligible repository occurrence."""

import json
import re
from collections import Counter
from itertools import product
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal
from urllib.parse import urlencode

from pydantic import Field, field_validator, model_validator

from vulnproof.artifacts import read_local
from vulnproof.correlation.engine import MAX_DOCUMENT_BYTES
from vulnproof.correlation.repository import digest, document
from vulnproof.discovery.repository import discover
from vulnproof.models.common import Contract, RelativePath, Sha256, relative_path
from vulnproof.provenance.models import fingerprint
from vulnproof.runner.control_driver import request_target
from vulnproof.static.repository import ScanInput

from .engine import PlanningFailure, planning_catalog

Name = Annotated[str, Field(min_length=1, max_length=256)]
FIELDS = ("entry_point", "method", "route", "query_key")


class FixedQuery(Contract):
    name: Name
    value: str = Field(max_length=4096)


class Endpoint(Contract):
    file: RelativePath
    handler: Name
    entry_point: Name | None = None
    method: Literal["GET"] | None = None
    route: Name | None = None
    query_key: Name | None = None
    path_parameter: Name | None = None
    download_root: Name | None = None
    control_value: Name | None = None
    control_sha256: Sha256 | None = None
    fixed_query: tuple[FixedQuery, ...] | None = Field(default=None, max_length=64)

    @field_validator("entry_point")
    @classmethod
    def target(cls, value: str | None) -> str | None:
        if value is not None:
            filename, _, symbol = value.partition(":")
            if not relative_path(filename).endswith(".py") or not symbol.isidentifier():
                raise ValueError("Expected captured Python file and application symbol")
        return value

    @field_validator("download_root", "route")
    @classmethod
    def absolute_path(cls, value: str | None) -> str | None:
        if value is not None and (
            not value.startswith("/")
            or value.startswith("//")
            or ".." in PurePosixPath(value).parts
            or any(c in value for c in "?#\\")
            or not value.isprintable()
        ):
            raise ValueError("Expected an absolute local path")
        return value

    @field_validator("control_value")
    @classmethod
    def legitimate_document(cls, value: str | None) -> str | None:
        if value is not None:
            relative_path(value)
            if not value.isprintable():
                raise ValueError("Expected printable relative document name")
        return value


class Configuration(Contract):
    schema_version: Literal["1.0", "1.1", "1.2"]
    endpoints: tuple[Endpoint, ...] = Field(max_length=256)

    @model_validator(mode="after")
    def versioned_parameters(self) -> Configuration:
        for endpoint in self.endpoints:
            if endpoint.path_parameter is not None and (
                self.schema_version != "1.2" or endpoint.query_key is not None
            ):
                raise ValueError("Path parameters require configuration 1.2 without query_key")
            if endpoint.fixed_query is not None:
                if self.schema_version not in ("1.1", "1.2"):
                    raise ValueError("Fixed query parameters require configuration 1.1")
                names = [p.name for p in endpoint.fixed_query]
                if len(set(names)) != len(names) or endpoint.query_key in names:
                    raise ValueError("Duplicate or conflicting fixed query parameter")
        return self


def unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    decoded = dict(pairs)
    if len(decoded) != len(pairs):
        raise ValueError("Duplicate JSON field")
    return decoded


def read(path: Path, limit: int) -> bytes:
    return read_local(path.absolute().parent, path.name, limit)


def disposition(
    row: dict[str, Any],
    paths: dict[str, Any],
    analysis: str,
    profiles: dict[tuple[str, str], Endpoint],
    captured: set[str],
) -> dict[str, Any]:
    out: dict[str, Any] = {**row, "status": "blocked", "reasons": []}
    reasons: list[str] = out["reasons"]
    if analysis != "completed":
        reasons.append("analysis_" + analysis)
    if row["correlation_status"] != "single_candidate" and row["correlation_status"] not in reasons:
        reasons.append(row["correlation_status"])
    if reasons:
        return out
    path_ids = next(iter(row["candidates"].values()))
    alternatives = []
    for pid in path_ids:
        for index, b in enumerate(paths[pid]["bindings"]):
            handler = (b["handler_location"]["path"], b["handler"])
            app = b["application_location"]
            target = f"{app['path']}:{b['application_symbol']}" if app else None
            route = b["route_parts"]
            for method, key in product(
                route["methods"] or [None], [i["name"] for i in b["inputs"]] or [None]
            ):
                alternatives.append((handler, (target, method, route["route"], key), pid, index))
                if len(alternatives) > 4096:
                    raise PlanningFailure("plan_limit", "Too many endpoint alternatives")
    if not alternatives:
        reasons.extend(
            sorted({g for pid in path_ids for g in paths[pid]["gaps"]} or {"handler_unresolved"})
        )
        return out
    selected_handlers = {handler for handler, *_ in alternatives if handler in profiles}
    choices: dict[tuple[object, ...], list[dict[str, Any]]] = {}
    conflicts = []
    for handler, observed, pid, index in alternatives:
        if selected_handlers and handler not in selected_handlers:
            continue
        profile = profiles.get(handler)
        values = []
        origins = {}
        mismatches = {}
        for field, fact in zip(FIELDS, observed, strict=True):
            declared = (
                profile.path_parameter
                if profile
                and field == "query_key"
                and isinstance(observed[2], str)
                and "<path:" in observed[2]
                else getattr(profile, field, None)
            )
            if fact is not None and declared is not None and fact != declared:
                mismatches[field] = {"observed": fact, "declared": declared}
            values.append(fact if fact is not None else declared)
            origins[field] = (
                "observed"
                if fact is not None
                else "declared"
                if declared is not None
                else "missing"
            )
        if mismatches:
            conflicts.append(
                {"handler": handler, "path_id": pid, "binding_index": index, "fields": mismatches}
            )
            continue
        choices.setdefault((handler, *values), []).append(
            {"path_id": pid, "binding_index": index, "origins": origins}
        )
    # A declaration may select a known alternative. A gap on a different path
    # cannot corroborate a declaration contradicted by the observed alternatives.
    for conflict in conflicts:
        if not any(
            identity[0] == conflict["handler"]
            and all(s["origins"][field] == "observed" for field in conflict["fields"])
            for identity, support in choices.items()
            for s in support
        ):
            out["conflicts"] = conflicts
            reasons.append("configuration_conflict")
            return out
    if len(choices) != 1:
        reasons.append("endpoint_selection_required")
        return out
    identity, support = next(iter(choices.items()))
    endpoint_key, entry_point, method, route, query_key = identity
    assert isinstance(endpoint_key, tuple)
    profile = profiles.get(endpoint_key)
    out.update(
        handler_file=endpoint_key[0],
        handler=endpoint_key[1],
        support=support,
        entry_point=entry_point,
        method=method,
        route=route,
        query_key=query_key,
    )
    for field, value in zip(FIELDS, identity[1:], strict=True):
        if not value:
            reasons.append(field + "_required")
    if method and method != "GET":
        reasons.append("unsupported_method")
    path_input = (
        isinstance(route, str)
        and isinstance(query_key, str)
        and route.count("<path:" + query_key + ">") == 1
        and re.search(r"[<>]", route.replace("<path:" + query_key + ">", "")) is None
    )
    if path_input and not any(
        b.get("kind") == "path" and b.get("name") == query_key
        for s in support
        for b in paths[s["path_id"]]["bindings"][s["binding_index"]]["inputs"]
    ):
        reasons.append("path_parameter_unresolved")
    if isinstance(route, str) and (
        (("<" in route or ">" in route) and not path_input)
        or not route.startswith("/")
        or route.startswith("//")
        or any(ch in route for ch in "?#\\")
        or not route.isprintable()
    ):
        reasons.append("literal_route_required")
    if isinstance(entry_point, str) and entry_point.partition(":")[0] not in captured:
        reasons.append("entry_point_outside_capture")
    root = profile.download_root if profile else None
    if not root:
        reasons.append("download_root_required")
    elif PurePosixPath("/tmp/vulnproof").is_relative_to(root):
        reasons.append("canary_inside_download_root")
    if not profile or not profile.control_value or not profile.control_sha256:
        reasons.append("control_required")
    if reasons:
        return out
    assert profile and isinstance(query_key, str) and isinstance(route, str)
    out.update(
        status="draft",
        template_id="cwe22-file-read-v1",
        download_root=root,
        control={
            "request_target": route + "?" + urlencode({query_key: profile.control_value}),
            "status": 200,
            "body_sha256": profile.control_sha256,
        },
        prerequisites=[
            "source_bound_image_required",
            "execution_authorization_required",
            "runtime_oracle_required",
        ],
    )
    if profile.fixed_query is not None or path_input:
        assert profile.control_value is not None
        request = {
            "schema_version": "1.1" if path_input else "1.0",
            "route": route,
            "query_key": query_key,
            "fixed_query": [p.model_dump() for p in (profile.fixed_query or ())],
            "control_value": profile.control_value,
        }
        out["control"]["request_target"] = request_target(request, profile.control_value)
        out["http_request"] = request
    return out


def plan_repository(
    scan: Path, investigation: Path, correlation: Path, discovery: Path, config: Path | None
) -> str:
    try:
        supplied = read(discovery, MAX_DOCUMENT_BYTES)
        details: dict[tuple[str, int], dict[str, object]] = {}
        rebuilt = json.loads(discover(scan, investigation, correlation, route_parts=details))
        supplied_json = json.loads(supplied, object_pairs_hook=unique_fields)
        if json.dumps(supplied_json, sort_keys=True) != json.dumps(rebuilt, sort_keys=True):
            raise PlanningFailure("discovery_mismatch", "Discovery differs from retained evidence")
        for (pid, index), parts in details.items():
            rebuilt["paths"][pid]["bindings"][index]["route_parts"] = parts
        manifest = ScanInput.model_validate_json(read_local(scan, "scan.json", MAX_DOCUMENT_BYTES))
        if fingerprint(manifest.files) != rebuilt["source_fingerprint"]:
            raise PlanningFailure("source_changed", "Source manifest changed during planning")
        captured = {f.path for f in manifest.files}
        profiles = {}
        raw_config = None
        if config is not None:
            raw_config = read(config, 1024 * 1024)
            json.loads(raw_config, object_pairs_hook=unique_fields)
            for profile in Configuration.model_validate_json(raw_config).endpoints:
                key = (profile.file, profile.handler)
                if key in profiles:
                    raise PlanningFailure(
                        "duplicate_endpoint", "Expected one profile per file and handler"
                    )
                profiles[key] = profile
        rows = [
            disposition(r, rebuilt["paths"], rebuilt["analysis_outcome"], profiles, captured)
            for r in rebuilt["findings"]
        ]
        catalog = planning_catalog()
        return document(
            {
                **rebuilt,
                "schema_version": "1.2"
                if any(r.get("http_request", {}).get("schema_version") == "1.1" for r in rows)
                else (json.loads(raw_config)["schema_version"] if raw_config else "1.0"),
                "findings": rows,
                "counts": Counter(r["status"] for r in rows),
                "discovery_sha256": digest(supplied),
                "config_sha256": digest(raw_config) if raw_config else None,
                "declared_endpoints": [p.model_dump(exclude_none=True) for p in profiles.values()],
                "template": catalog.template.model_dump(),
                "execution_authorized": False,
            }
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, PlanningFailure):
            raise
        raise PlanningFailure(
            "invalid_planning_input", "Invalid configuration, evidence, or planning output limit"
        ) from exc
