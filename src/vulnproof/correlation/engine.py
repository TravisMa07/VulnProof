"""Verify retained inputs and correlate only the reviewed fixture profile."""

import hashlib
import os
import stat
from importlib.resources import files
from pathlib import Path

from vulnproof.ingest import IngestionDocument
from vulnproof.models import Artifact, Reason
from vulnproof.models.common import relative_path
from vulnproof.provenance import CaptureFailure, verify_capture
from vulnproof.provenance.filesystem import open_root, scan_tree
from vulnproof.static import AnalysisDocument, AnalysisFailure
from vulnproof.static.analysis import admit_fixture
from vulnproof.static.models import MAX_LOG_BYTES, MAX_SARIF_BYTES, QueryResult
from vulnproof.static.sarif import normalize_sarif

from .models import CompatibilityPolicy, CorrelationDocument, FindingCorrelation

MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_CANDIDATES = 4096
MAX_CANDIDATE_LOCATIONS = 100_000


class CorrelationFailure(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def policy() -> CompatibilityPolicy:
    definition = files("vulnproof.correlation").joinpath("rules/cwe22-file-read.yaml").read_bytes()
    return CompatibilityPolicy(rule_sha256=hashlib.sha256(definition).hexdigest())


def _read(root: Path, path: str, limit: int) -> bytes:
    """Bounded descriptor-relative regular-file reads, with no symlink components."""
    relative_path(path)
    with open_root(root) as root_fd:
        descriptor = os.dup(root_fd)
        try:
            parts = path.split("/")
            for part in parts[:-1]:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
                )
                os.close(descriptor)
                descriptor = child
            child = os.open(
                parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor
            )
            with os.fdopen(child, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("artifact is not a regular file")
                data = stream.read(limit + 1)
            if len(data) > limit:
                raise ValueError("artifact exceeds limit")
            return data
        finally:
            os.close(descriptor)


def _artifact(root: Path, artifact: Artifact, limit: int) -> bytes:
    data = _read(root, artifact.path, limit)
    if artifact.sha256 != hashlib.sha256(data).hexdigest() or artifact.size_bytes != len(data):
        raise ValueError("artifact hash or size mismatch")
    return data


def correlate(capture: Path, analysis: Path) -> CorrelationDocument:
    """No tool or application execution; changed/inconsistent inputs fail closed."""
    try:
        return _correlate(capture.absolute(), analysis.absolute())
    except CorrelationFailure:
        raise
    except (ValueError, OSError, CaptureFailure, AnalysisFailure) as exc:
        raise CorrelationFailure(
            "invalid_correlation_input",
            "Capture or analysis is unreadable, modified, unsupported, or inconsistent",
        ) from exc


def _correlate(capture: Path, analysis: Path) -> CorrelationDocument:
    provenance = verify_capture(capture)
    ingestion_bytes = _read(capture, "ingestion.json", MAX_DOCUMENT_BYTES)
    if hashlib.sha256(ingestion_bytes).hexdigest() != provenance.ingestion_sha256:
        raise ValueError("ingestion changed")
    ingestion = IngestionDocument.model_validate_json(ingestion_bytes)
    analysis_bytes = _read(analysis, "analysis.json", MAX_DOCUMENT_BYTES)
    report = AnalysisDocument.model_validate_json(analysis_bytes)
    if report.snapshot != provenance.snapshot:
        raise CorrelationFailure("source_mismatch", "Analysis must reference the selected capture")
    fixture = admit_fixture(provenance.snapshot.fingerprint)
    if report.fixture_id != fixture.id:
        raise ValueError("fixture identity mismatch")
    if len(report.commands) > 3 or len({c.stage for c in report.commands}) != len(report.commands):
        raise ValueError("invalid command history")
    for command in report.commands:
        _artifact(analysis, command.log, MAX_LOG_BYTES)
    raw = None
    if report.raw_sarif is not None:
        raw = _artifact(analysis, report.raw_sarif, MAX_SARIF_BYTES)
    if report.outcome == "completed":
        with open_root(analysis / "work/source") as descriptor:
            tree = scan_tree(descriptor)
        if tree.files != provenance.files or tree.excluded_paths:
            raise ValueError("analysis copy differs from capture")
        assert raw is not None
        results, notes = normalize_sarif(raw, analysis / "work/source", provenance.files)
        if results != report.results or notes != report.diagnostics:
            raise ValueError("normalized analysis differs from retained SARIF")
    selected_policy = policy()
    bindings = {b.finding_id: b for b in provenance.bindings}
    entries: list[FindingCorrelation] = []
    candidate_count = location_count = 0
    for imported in ingestion.findings:
        finding = imported.finding
        reasons = [
            Reason(
                code="scanner_source_unverified",
                message="Scanner source bytes and rule definition are not authenticated",
            )
        ]
        candidates: tuple[QueryResult, ...] = ()
        status: str
        if finding.rule_id != selected_policy.rule_id or "CWE-22" not in finding.cwes:
            status = "unsupported_mapping"
            reasons.append(
                Reason(code=status, message="No reviewed scanner rule/CWE mapping applies")
            )
        elif bindings[finding.id].location != "present":
            status = "location_unavailable"
            reasons.extend(bindings[finding.id].reasons)
        elif report.outcome == "failed":
            status = "analysis_failed"
            reasons.extend(report.diagnostics)
        else:
            candidates = tuple(
                r
                for r in report.results
                if r.paths and r.sink is not None and r.sink.overlaps(finding.location)
            )
            status = (
                "ambiguous"
                if len(candidates) > 1
                else ("single_candidate" if candidates else "no_candidate")
            )
            reasons.append(
                Reason(
                    code=status,
                    message="Candidates use the reviewed mapping and overlapping sinks; "
                    "absence of candidates does not establish safety",
                )
            )
            if any(
                loc.start_column is None or loc.end_column is None
                for loc in (finding.location, *(r.sink for r in candidates if r.sink))
            ):
                reasons.append(
                    Reason(
                        code="limited_location_precision",
                        message="Some regions lack columns; line overlap is less precise",
                    )
                )
        if report.normalization == "partial":
            reasons.append(
                Reason(
                    code="analysis_partial",
                    message="Unrepresentable results or paths may hide other candidates",
                )
            )
        candidate_count += len(candidates)
        location_count += sum(len(p.path.locations) for r in candidates for p in r.paths)
        if candidate_count > MAX_CANDIDATES or location_count > MAX_CANDIDATE_LOCATIONS:
            raise CorrelationFailure("correlation_limit", "Candidate output exceeds bounded limits")
        entries.append(
            FindingCorrelation.model_validate(
                {
                    "imported": imported,
                    "status": status,
                    "candidates": candidates,
                    "reasons": tuple(reasons),
                }
            )
        )
    # Recheck the capture and report to catch ordinary changes during consumption.
    if (
        verify_capture(capture) != provenance
        or _read(analysis, "analysis.json", MAX_DOCUMENT_BYTES) != analysis_bytes
    ):
        raise ValueError("inputs changed during correlation")
    return CorrelationDocument(
        schema_version="1.0",
        policy=selected_policy,
        snapshot=provenance.snapshot,
        ingestion_sha256=provenance.ingestion_sha256,
        ingestion_status=ingestion.status,
        analysis_sha256=hashlib.sha256(analysis_bytes).hexdigest(),
        analysis_id=report.id,
        analysis_outcome=report.outcome,
        analysis_normalization=report.normalization,
        raw_sarif_sha256=report.raw_sarif.sha256 if report.raw_sarif else None,
        findings=tuple(entries),
        diagnostics=report.diagnostics
        + tuple(
            Reason(code=d.code, message=f"Ingestion {d.severity} at {d.pointer}: {d.message}")
            for d in ingestion.diagnostics
        ),
    )
