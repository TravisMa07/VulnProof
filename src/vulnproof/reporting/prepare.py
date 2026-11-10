"""Read bounded retained artifacts safely; never execute analysis or applications."""

import base64
import hashlib
from pathlib import Path

from vulnproof.artifacts import read_local
from vulnproof.models import Artifact, EvidenceBundle, ExecutionEvidence, Reason
from vulnproof.validation.models import Attempt

from .models import ArtifactCheck, ReportDocument, RuntimeDetail, integrity_state

MAX_RESULT_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_ARTIFACTS = 256
MAX_PREVIEW_BYTES = 16 * 1024
MAX_TOTAL_PREVIEW_BYTES = 256 * 1024


class ReportFailure(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def preview(data: bytes, limit: int) -> tuple[str, str, bool]:
    if limit == 0:
        return "none", "", bool(data)
    sample = data[:limit]
    try:
        # Classify by the complete bounded artifact, so a binary tail is not hidden.
        decoded = data.decode("utf-8")
        if any(not c.isprintable() and c not in "\n\r\t" for c in decoded):
            raise ValueError("binary controls")
        text = sample.decode("utf-8", errors="replace")
        return "utf-8", text, len(data) > len(sample)
    except UnicodeError, ValueError:
        return "base64", base64.b64encode(sample).decode("ascii"), len(data) > len(sample)


def inspect_artifact(
    root: Path, ref: Artifact, remaining: int, preview_remaining: int
) -> tuple[ArtifactCheck, bytes | None]:
    limit = min(MAX_ARTIFACT_BYTES, remaining)
    if limit <= 0:
        return ArtifactCheck(
            artifact=ref,
            status="limit_exceeded",
            reasons=(
                Reason(
                    code="artifact_budget",
                    message="Aggregate artifact read budget exhausted; file was not read",
                ),
            ),
        ), None
    try:
        data = read_local(root, ref.path, limit)
    except FileNotFoundError:
        return ArtifactCheck(
            artifact=ref,
            status="missing",
            reasons=(Reason(code="artifact_missing", message="Referenced artifact is missing"),),
        ), None
    except ValueError as exc:
        limited = str(exc) == "artifact exceeds limit"
        return ArtifactCheck(
            artifact=ref,
            status="limit_exceeded" if limited else "unreadable",
            reasons=(
                Reason(
                    code="artifact_limit" if limited else "unsafe_artifact",
                    message="Artifact exceeded its read bound"
                    if limited
                    else "Artifact is not an allowed regular file",
                ),
            ),
        ), None
    except OSError:
        return ArtifactCheck(
            artifact=ref,
            status="unreadable",
            reasons=(
                Reason(
                    code="artifact_unreadable",
                    message="Artifact could not be read without following symlinks",
                ),
            ),
        ), None
    digest = hashlib.sha256(data).hexdigest()
    reasons = []
    changed = (ref.sha256 is not None and ref.sha256 != digest) or (
        ref.size_bytes is not None and ref.size_bytes != len(data)
    )
    if changed:
        reasons.append(
            Reason(
                code="artifact_changed",
                message="Observed artifact hash or size differs from the retained descriptor",
            )
        )
    if ref.sha256 is None or ref.size_bytes is None:
        reasons.append(Reason(code="metadata_missing", message="Retained hash or size is unknown"))
    if ref.truncated is not False:
        reasons.append(
            Reason(
                code="artifact_truncated" if ref.truncated else "truncation_unknown",
                message="Artifact is truncated"
                if ref.truncated
                else "Artifact completeness is unknown",
            )
        )
    status = "changed" if changed else "incomplete" if reasons else "verified"
    if not reasons:
        reasons.append(
            Reason(
                code="artifact_verified",
                message="Observed bytes match retained hash and size; declared complete",
            )
        )
    encoding, text, truncated = preview(data, min(MAX_PREVIEW_BYTES, preview_remaining))
    return ArtifactCheck.model_validate(
        {
            "artifact": ref,
            "status": status,
            "observed_sha256": digest,
            "observed_size_bytes": len(data),
            "preview_encoding": encoding,
            "preview": text,
            "preview_truncated": truncated,
            "reasons": tuple(reasons),
        }
    ), data


def runtime_detail(
    execution: ExecutionEvidence,
    checks: dict[str, ArtifactCheck],
    data: dict[str, bytes],
    evidence: EvidenceBundle,
) -> RuntimeDetail:
    ref_id = next((r for r in execution.artifact_ids if r == "validation:attempt"), None)
    if ref_id is None or checks[ref_id].status != "verified":
        return RuntimeDetail(
            execution_id=execution.id,
            artifact_id=ref_id,
            status="unavailable",
            reason=Reason(
                code="runtime_detail_unavailable",
                message="No complete verified supported attempt artifact is available",
            ),
        )
    try:
        attempt = Attempt.model_validate_json(data[ref_id])
        snapshot = next(
            (s for s in evidence.snapshots if s.id == execution.source.observed_snapshot_id), None
        )
        observed = attempt.driver is not None and attempt.driver.observed
        if (
            attempt.finding_id != execution.finding_id
            or attempt.image.image_id != execution.image_id
            or attempt.path_id != execution.static_path_id
            or snapshot is None
            or attempt.image.source_fingerprint != snapshot.fingerprint
            or (execution.oracle == "observed") != observed
            or (execution.outcome == "completed") != (attempt.execution == "completed")
        ):
            raise ValueError("attempt relationships differ")
    except ValueError:
        return RuntimeDetail(
            execution_id=execution.id,
            artifact_id=ref_id,
            status="invalid",
            reason=Reason(
                code="runtime_detail_invalid",
                message="Attempt contract is unsupported, invalid, or disagrees with the evidence bundle; raw preview remains available",
            ),
        )
    return RuntimeDetail(
        execution_id=execution.id,
        artifact_id=ref_id,
        status="available",
        attempt=attempt,
        reason=Reason(
            code="runtime_detail_available",
            message="Parsed supported attempt matches the retained execution references",
        ),
    )


def prepare_report(root: Path) -> ReportDocument:
    try:
        raw = read_local(root.absolute(), "result.json", MAX_RESULT_BYTES)
        evidence = EvidenceBundle.model_validate_json(raw)
        if len(evidence.artifacts) > MAX_ARTIFACTS:
            raise ReportFailure(
                "artifact_count_limit", "Report supports at most 256 artifact descriptors"
            )
        remaining = MAX_TOTAL_BYTES
        preview_remaining = MAX_TOTAL_PREVIEW_BYTES
        checks = []
        runtime_data = {}
        for ref in evidence.artifacts:
            check, data = inspect_artifact(root.absolute(), ref, remaining, preview_remaining)
            checks.append(check)
            if data is not None:
                remaining -= len(data)
                preview_remaining -= min(len(data), MAX_PREVIEW_BYTES, preview_remaining)
                if ref.id == "validation:attempt":
                    runtime_data[ref.id] = data
            elif check.status == "limit_exceeded":
                # A bounded read can consume the entire remaining allowance before failing.
                remaining -= min(MAX_ARTIFACT_BYTES, remaining)
        indexed = {c.artifact.id: c for c in checks}
        details = tuple(
            runtime_detail(e, indexed, runtime_data, evidence) for e in evidence.execution_evidence
        )
        integrity = integrity_state(tuple(checks))
        warnings = [
            Reason(
                code="recorded_assessment_only",
                message="This report presents a recorded assessment; rendering and matching local hashes do not independently validate exploitability or authenticate the producer",
            )
        ]
        if integrity != "verified":
            warnings.append(
                Reason(
                    code="evidence_integrity_" + integrity,
                    message="Retained artifact evidence is incomplete or failed integrity checks; the recorded assessment is preserved without endorsement",
                )
            )
        warnings.extend(d.reason for d in details if d.status != "available")
        if read_local(root.absolute(), "result.json", MAX_RESULT_BYTES) != raw:
            raise ReportFailure("result_changed", "Result changed during report preparation")
        return ReportDocument(
            schema_version="1.0",
            profile="single-validation-report-v1",
            result_sha256=hashlib.sha256(raw).hexdigest(),
            evidence=evidence,
            integrity=integrity,
            artifacts=tuple(checks),
            runtime=details,
            warnings=tuple(warnings),
        )
    except ReportFailure:
        raise
    except (ValueError, OSError, RecursionError) as exc:
        raise ReportFailure(
            "invalid_report_input",
            "Result is unreadable, outside the supported contract, or over its size bound",
        ) from exc
