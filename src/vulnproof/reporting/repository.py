"""Offline repository reporting: retained assessments and independent integrity observations."""

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from vulnproof.artifacts import read_local
from vulnproof.models.common import Contract, Sha256
from vulnproof.planning.repository import plan_repository, unique_fields
from vulnproof.runner.controls import RepositoryControlAttempt
from vulnproof.runner.repository import sha
from vulnproof.static.repository import Investigation, ScanInput
from vulnproof.validation.repository import RepositoryValidation, classify

from .engine import publish_report
from .models import ArtifactCheck, Integrity
from .prepare import (
    MAX_ARTIFACTS,
    MAX_RESULT_BYTES,
    MAX_TOTAL_BYTES,
    MAX_TOTAL_PREVIEW_BYTES,
    ReportFailure,
    inspect_artifact,
)


class PathSupport(BaseModel):
    path_id: str


class PlanRow(BaseModel):
    finding_id: str
    status: Literal["draft", "blocked"]
    correlation_status: str
    candidates: dict[str, list[str]]
    reasons: list[str]
    support: list[PathSupport] = Field(default_factory=list)


class RetainedPlan(BaseModel):
    schema_version: Literal["1.0", "1.1", "1.2"]
    source_fingerprint: Sha256
    scanner_source_state: Literal["controlled_snapshot", "unverified"]
    paths: dict[str, Any]
    findings: list[PlanRow] = Field(max_length=10000)


class ValidationDetail(Contract):
    label: str
    result_sha256: Sha256 | None
    result: RepositoryValidation | None
    warnings: tuple[str, ...]
    artifacts: tuple[ArtifactCheck, ...]


class RepositoryReport(Contract):
    schema_version: Literal["1.0"] = "1.0"
    profile: Literal["repository-evidence-report-v1"] = "repository-evidence-report-v1"
    plan_sha256: Sha256
    plan: dict[str, Any]
    correlation: dict[str, Any] | None
    investigation: Investigation | None
    excerpts: dict[str, str]
    integrity: Integrity
    warnings: tuple[str, ...]
    validations: tuple[ValidationDetail, ...]
    artifacts: tuple[ArtifactCheck, ...]


def document(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw, object_pairs_hook=unique_fields)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def prepare_repository_report(
    *,
    scan: Path,
    investigation: Path,
    correlation: Path,
    discovery: Path,
    plan: Path,
    config: Path | None,
    validations: tuple[Path, ...],
) -> RepositoryReport:
    if len(validations) > 64 or len({p.resolve() for p in validations}) != len(validations):
        raise ReportFailure("invalid_validation_selection", "Select at most 64 distinct attempts")
    remaining = MAX_TOTAL_BYTES

    def bounded_read(path: Path) -> bytes:
        nonlocal remaining
        if remaining <= 0:
            raise ValueError("Aggregate evidence read budget exceeded")
        data = read_local(path.absolute().parent, path.name, min(MAX_RESULT_BYTES, remaining))
        remaining -= len(data)
        return data

    try:
        raw = bounded_read(plan)
        RetainedPlan.model_validate_json(raw)
        retained = document(raw)
        rows = retained["findings"]
        if (
            retained["schema_version"] not in ("1.0", "1.1", "1.2")
            or not isinstance(rows, list)
            or not isinstance(retained["paths"], dict)
        ):
            raise ValueError("Invalid repository plan")
        ids = [row["finding_id"] for row in rows]
        if len(set(ids)) != len(ids) or not all(isinstance(i, str) for i in ids):
            raise ValueError("Duplicate occurrence identity")
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise ReportFailure(
            "invalid_report_plan", "A readable repository plan is required"
        ) from exc
    warnings: list[str] = []
    integrity: Integrity = "verified"
    try:
        rebuilt = document(
            plan_repository(scan, investigation, correlation, discovery, config).encode()
        )
        if rebuilt != retained:
            raise ValueError("Plan differs from reconstructed evidence")
    except OSError, ValueError, KeyError, TypeError, RecursionError:
        integrity = "failed"
        warnings.append(
            "Upstream evidence could not reproduce this plan. All flows below are retained claims, not verified associations."
        )
    links = None
    analysis = None
    try:
        links = document(bounded_read(correlation))
        if not isinstance(links.get("findings"), list) or any(
            not isinstance(r, dict)
            or not isinstance(r.get("finding"), dict)
            or not isinstance(r["finding"].get("id"), str)
            for r in links["findings"]
        ):
            links = None
            raise ValueError("Malformed correlation inventory")
        analysis = Investigation.model_validate_json(
            bounded_read(investigation / "investigation.json")
        )
    except OSError, ValueError, RecursionError:
        warnings.append(
            "Some scanner or CodeQL details are unavailable; no missing detail was inferred."
        )
        integrity = "failed"
    excerpts: dict[str, str] = {}
    if analysis and integrity == "verified":
        try:
            manifest = ScanInput.model_validate_json(bounded_read(scan / "scan.json"))
            hashes = {f.path: f.sha256 for f in manifest.files}
            sources: dict[str, list[str]] = {}
            for query in analysis.results:
                for path in query.paths:
                    for location in path.path.locations:
                        key = f"{location.path}:{location.start_line}"
                        if key in excerpts:
                            continue
                        if len(excerpts) >= 1024 or len(sources) >= 128:
                            warnings.append(
                                "Source excerpt budget reached; other nodes retain locations only."
                            )
                            raise StopIteration
                        if location.path not in sources:
                            data = bounded_read(scan / "snapshot" / location.path)
                            if sha(data) != hashes.get(location.path):
                                raise ValueError("Source excerpt changed")
                            sources[location.path] = data.decode(
                                "utf-8", errors="replace"
                            ).splitlines()
                        lines = sources[location.path]
                        start = max(0, location.start_line - 2)
                        excerpt = "\n".join(
                            f"{i + 1}: {lines[i]}"
                            for i in range(start, min(len(lines), location.start_line + 1))
                        )
                        excerpts[key] = excerpt[:1600] + (
                            "\n[excerpt truncated]" if len(excerpt) > 1600 else ""
                        )
        except StopIteration:
            pass
        except OSError, ValueError:
            integrity = "failed"
            excerpts.clear()
            warnings.append("Source excerpts could not be checked against the captured manifest.")
    preview_remaining = MAX_TOTAL_PREVIEW_BYTES
    artifact_count = 0

    def checks(root: Path, references: list[Any]) -> tuple[ArtifactCheck, ...]:
        nonlocal remaining, preview_remaining, artifact_count, integrity
        found = []
        for ref in references:
            artifact_count += 1
            check, data = inspect_artifact(
                root, ref, remaining if artifact_count <= MAX_ARTIFACTS else 0, preview_remaining
            )
            if data is not None:
                remaining -= len(data)
                preview_remaining -= min(len(data), 16 * 1024, preview_remaining)
            if check.status != "verified" and integrity != "failed":
                integrity = "failed" if check.status in ("changed", "unreadable") else "incomplete"
            found.append(check)
        return tuple(found)

    artifacts = (
        checks(
            investigation,
            [c.log for c in analysis.commands]
            + ([analysis.raw_sarif] if analysis.raw_sarif else []),
        )
        if analysis
        else ()
    )
    details = []
    for index, directory in enumerate(validations, 1):
        notes: list[str] = []
        result = None
        digest = None
        observed: tuple[ArtifactCheck, ...] = ()
        try:
            data = bounded_read(directory / "result.json")
            digest = sha(data)
            result = RepositoryValidation.model_validate_json(data)
            selected = [r for r in rows if r["finding_id"] == result.finding_id]
            if (
                len(selected) != 1
                or result.finding != selected[0]
                or result.plan_sha256 != sha(raw)
                or result.source_fingerprint != retained["source_fingerprint"]
                or result.scanner_source_state != retained["scanner_source_state"]
                or bounded_read(directory / "plan.json") != raw
            ):
                notes.append("Result does not match the selected plan and source identity.")
            attempt = result.attempt
            if attempt:
                if (
                    attempt.finding_id != result.finding_id
                    or attempt.plan_sha256 != sha(raw)
                    or attempt.source_fingerprint != result.source_fingerprint
                    or attempt.scanner_source_state != result.scanner_source_state
                    or attempt.profile != "repository-validation-attempt-v1"
                ):
                    notes.append("Embedded attempt identity disagrees with the result.")
                if (
                    RepositoryControlAttempt.model_validate_json(
                        bounded_read(directory / "runtime/attempt.json")
                    )
                    != attempt
                ):
                    notes.append("Retained runtime attempt differs from the embedded attempt.")
                if selected:
                    row = selected[0]
                    if attempt.http_request != row.get("http_request"):
                        notes.append("Request profile differs from the plan.")
                    candidate = row.get("candidates", {}).get(attempt.candidate_result_id)
                    supporting = {s.get("path_id") for s in row.get("support", [])}
                    if (
                        candidate is None
                        or set(candidate) != set(attempt.path_ids)
                        or supporting != set(attempt.supporting_path_ids)
                    ):
                        notes.append("Attempt path references disagree with the retained plan.")
                    expected_request = {
                        **row.get("control", {}),
                        "entry_point": row.get("entry_point"),
                        "route": row.get("route"),
                        "query_key": row.get("query_key"),
                        "download_root": row.get("download_root"),
                    }
                    if any(
                        attempt.request.get(k) != v
                        for k, v in expected_request.items()
                        if k != "status"
                    ):
                        notes.append("Attempt request disagrees with the retained plan.")
                if classify(attempt)[0] != result.classification:
                    notes.append(
                        "Recorded classification contradicts its runtime observations; it is preserved, not replaced."
                    )
                observed = checks(directory / "runtime", [c.log for c in attempt.commands])
        except OSError, ValueError, KeyError, TypeError, RecursionError:
            notes.append(
                "Validation evidence is missing, invalid, unreadable, or exceeds its limit."
            )
        if notes:
            integrity = "failed"
        details.append(
            ValidationDetail(
                label=f"Attempt {index}",
                result_sha256=digest,
                result=result,
                warnings=tuple(notes),
                artifacts=observed,
            )
        )
    return RepositoryReport(
        plan_sha256=sha(raw),
        plan=retained,
        correlation=links,
        investigation=analysis,
        excerpts=excerpts,
        integrity=integrity,
        warnings=tuple(warnings),
        validations=tuple(details),
        artifacts=artifacts,
    )


def write_repository_report(
    *,
    scan: Path,
    investigation: Path,
    correlation: Path,
    discovery: Path,
    plan: Path,
    config: Path | None,
    validations: tuple[Path, ...],
    output: Path,
) -> RepositoryReport:
    from .repository_html import render_repository_html

    inputs = (scan, investigation, correlation, discovery, plan, *validations)
    if config:
        inputs += (config,)
    if any(
        a.resolve().is_relative_to(b.resolve())
        for source in inputs
        for a, b in ((output, source), (source, output))
    ):
        raise ReportFailure(
            "invalid_report_output", "Choose a new directory separate from evidence"
        )
    report = prepare_repository_report(
        scan=scan,
        investigation=investigation,
        correlation=correlation,
        discovery=discovery,
        plan=plan,
        config=config,
        validations=validations,
    )
    publish_report(
        plan,
        output,
        lambda: {
            "report.json": (report.model_dump_json(indent=2) + "\n").encode(),
            "report.html": render_repository_html(report).encode(),
        },
    )
    return report
