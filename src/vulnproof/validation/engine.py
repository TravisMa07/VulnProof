"""Reproduce retained plans, execute a fixed fixture operation, assemble evidence."""

import hashlib
from pathlib import Path
from typing import Literal

from vulnproof.artifacts import read_local
from vulnproof.models import (
    Assessment,
    EvidenceBundle,
    ExecutionEvidence,
    Reason,
    SourceBinding,
    SourceSnapshot,
    StaticEvidence,
    ToolIdentity,
)
from vulnproof.planning import PlanningDocument, PlanningFailure, create_plans
from vulnproof.provenance import CaptureFailure, verify_capture
from vulnproof.runner.docker import RunnerFailure
from vulnproof.runner.engine import publish
from vulnproof.scanning import ScanFailure, verify_scan
from vulnproof.static.models import AnalysisDocument
from vulnproof.static.process import artifact

from .models import Attempt, Preparation
from .preparation import approval_bytes, select_image
from .runtime import execute

LIMIT = 64 * 1024 * 1024


def classification(
    attempt: Attempt, *, source_verified: bool, integrity: bool
) -> tuple[Literal["confirmed", "inconclusive", "failed"], Reason]:
    if (
        not integrity
        or attempt.execution != "completed"
        or not attempt.policy_verified
        or attempt.cleanup != "verified_absent"
        or attempt.driver is None
    ):
        return "failed", Reason(
            code="validation_incomplete",
            message="Execution, integrity, or cleanup requirements failed; retained observations do not establish confirmation",
        )
    if not source_verified:
        return "inconclusive", Reason(
            code="scanner_source_unverified",
            message="Observed behavior cannot confirm this imported finding without verified scanner provenance",
        )
    if attempt.driver.observed:
        return "confirmed", Reason(
            code="fresh_canary_disclosed",
            message="A valid control and exact fresh-canary disclosure correlate with the selected source-bound static path",
        )
    return "inconclusive", Reason(
        code="canary_not_disclosed",
        message="Bounded probes did not disclose the canary; unsuccessful tests do not establish safety",
    )


def validate(
    *,
    capture: Path,
    analysis: Path,
    correlation: Path,
    plan: Path,
    preparation: Path,
    finding_id: str,
    socket: Path,
    output: Path,
    authorize_validation: bool,
    scan: Path | None = None,
    path_id: str | None = None,
) -> EvidenceBundle:
    if not authorize_validation:
        raise RunnerFailure(
            "authorization_required",
            "Explicit CWE-22 validation authorization is required; diagnostics authorization is insufficient",
        )
    try:
        return _validate(
            capture=capture.absolute(),
            analysis=analysis.absolute(),
            correlation=correlation.absolute(),
            plan=plan.absolute(),
            preparation=preparation.absolute(),
            finding_id=finding_id,
            socket=socket,
            output=output.absolute(),
            scan=scan.absolute() if scan else None,
            path_id=path_id,
        )
    except RunnerFailure:
        raise
    except (ValueError, OSError, CaptureFailure, PlanningFailure, ScanFailure) as exc:
        raise RunnerFailure(
            "invalid_validation_input",
            "Validation inputs are unreadable, inconsistent, or output is not new",
        ) from exc


def _validate(
    *,
    capture: Path,
    analysis: Path,
    correlation: Path,
    plan: Path,
    preparation: Path,
    finding_id: str,
    socket: Path,
    output: Path,
    scan: Path | None,
    path_id: str | None,
) -> EvidenceBundle:
    plan_data = read_local(plan.parent, plan.name, LIMIT)
    document = PlanningDocument.model_validate_json(plan_data)
    if document != create_plans(capture, analysis, correlation):
        raise RunnerFailure(
            "plan_mismatch", "Plan does not reproduce from current retained evidence"
        )
    provenance = verify_capture(capture)
    analysis_data = read_local(analysis, "analysis.json", LIMIT)
    static_report = AnalysisDocument.model_validate_json(analysis_data)
    entry = next((e for e in document.findings if e.finding_id == finding_id), None)
    original = next(
        (f for f in document.correlation.findings if f.imported.finding.id == finding_id), None
    )
    if entry is None or original is None:
        raise RunnerFailure("unknown_finding", "Select an occurrence from the reproduced plan")
    finding = original.imported.finding
    association = verify_scan(scan) if scan is not None else None
    if association is not None:
        pair = next((f for f in association.findings if f.original == finding), None)
        if pair is None or association.snapshot != provenance.snapshot:
            raise RunnerFailure(
                "scan_source_mismatch", "Controlled scan does not describe this finding and capture"
            )
        finding = pair.bound
    candidate = original.candidates[0] if entry.plan is not None else None
    selected_path = None
    if candidate is not None:
        if path_id is None and len(candidate.paths) != 1:
            raise RunnerFailure(
                "path_selection_required",
                "Select one explicit path from this candidate's alternatives",
            )
        selected_path = (
            next((p.path for p in candidate.paths if p.path.id == path_id), None)
            if path_id
            else candidate.paths[0].path
        )
        if selected_path is None:
            raise RunnerFailure(
                "invalid_path_selection",
                "Selected path is not a retained alternative of this candidate",
            )
    elif path_id is not None:
        raise RunnerFailure(
            "invalid_path_selection", "Blocked findings cannot select an execution path"
        )
    protected = [capture, analysis, plan, correlation, preparation]
    if scan is not None:
        protected.append(scan)
    if any(output.resolve().is_relative_to(p.resolve()) for p in protected):
        raise RunnerFailure("invalid_output", "Output must be outside retained input evidence")
    prepared_data = read_local(preparation.parent, preparation.name, LIMIT)
    prepared = Preparation.model_validate_json(prepared_data)
    image = select_image(prepared, document.fixture.fixture_id, provenance.snapshot.fingerprint)
    output.mkdir(mode=0o700)
    (output / "diagnostics").mkdir(mode=0o700)
    artifacts = []

    def retain(data: bytes, name: str, identity: str, *, truncated: bool = False) -> str:
        path = output / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
        artifacts.append(artifact(path, output, identity, truncated=truncated))
        return identity

    retain(plan_data, "plan.json", "validation:plan")
    retain(prepared_data, "preparation.json", "validation:preparation")
    retain(approval_bytes(), "approval.json", "validation:approval")
    retain(analysis_data, "analysis.json", "validation:analysis")
    retain(
        read_local(capture, "provenance.json", LIMIT), "provenance.json", "validation:provenance"
    )
    retain(read_local(capture, "ingestion.json", LIMIT), "ingestion.json", "validation:ingestion")
    for source_file in provenance.files:
        retain(
            read_local(capture, "source/" + source_file.path, LIMIT),
            "source/" + source_file.path,
            "source:" + source_file.sha256,
        )
    static_refs = ["validation:analysis"]
    for ref in (static_report.raw_sarif, *(c.log for c in static_report.commands)):
        if ref is not None:
            data = read_local(analysis, ref.path, LIMIT)
            if ref.sha256 != hashlib.sha256(data).hexdigest() or (
                candidate is not None and ref.truncated is not False
            ):
                raise RunnerFailure(
                    "incomplete_static_artifact", "Static support is changed or truncated"
                )
            static_refs.append(
                retain(
                    data, "static/" + ref.path, "static:" + ref.id, truncated=bool(ref.truncated)
                )
            )
    if association is not None:
        assert scan is not None
        for ref in association.proof_artifacts:
            data = read_local(scan, ref.path, LIMIT)
            if ref.sha256 != hashlib.sha256(data).hexdigest() or ref.truncated is not False:
                raise RunnerFailure(
                    "scan_artifact_changed", "Controlled-scan support changed during assembly"
                )
            retain(data, "scan/" + ref.path, "scan-proof:" + ref.id)
    blocked = entry.plan is None
    snapshots: tuple[SourceSnapshot, ...] = (provenance.snapshot,)
    binding = static_report.source
    if association is None:
        snapshots = (SourceSnapshot(id=finding.source.expected_snapshot_id), provenance.snapshot)
        binding = SourceBinding(
            expected_snapshot_id=finding.source.expected_snapshot_id,
            observed_snapshot_id=provenance.snapshot.id,
            state="unverified",
            reason=Reason(
                code="scanner_source_unverified",
                message="Captured execution source is known, but its relationship to the imported report is unverified",
            ),
        )
    reason = Reason(
        code=original.status,
        message="No eligible unique complete candidate; no validation executed",
    )
    observed_paths = tuple(p.path for result in original.candidates for p in result.paths)
    static_outcome: Literal["path_found", "no_path_found", "unsupported", "failed"] = (
        "path_found"
        if observed_paths
        else "failed"
        if original.status == "analysis_failed"
        else "unsupported"
        if original.status == "unsupported_mapping"
        else "no_path_found"
    )
    static = StaticEvidence(
        id="validation:static",
        finding_id=finding.id,
        tool=static_report.tool or ToolIdentity(name="CodeQL"),
        rule_id=static_report.query_id,
        cwe="CWE-22",
        source=binding,
        outcome=static_outcome,
        paths=observed_paths,
        reasons=() if candidate else (reason,),
        artifact_ids=tuple(static_refs),
    )
    result: Literal["confirmed", "inconclusive", "unsupported", "failed"]
    attempt = None
    interrupted = False
    integrity = True
    execution_refs: tuple[str, ...] = ()
    if not blocked:
        assert candidate is not None and selected_path is not None
        try:
            attempt = execute(
                image=image,
                prepared=prepared,
                preparation_data=prepared_data,
                plan_data=plan_data,
                finding_id=finding_id,
                candidate_id=candidate.id,
                path_id=selected_path.id,
                socket=socket,
                output=output,
                authorize_validation=True,
            )
        except KeyboardInterrupt:
            interrupted = True
            attempt = Attempt.model_validate_json(read_local(output, "attempt.json", LIMIT))
        execution_refs = (
            retain(read_local(output, "attempt.json", LIMIT), "attempt.json", "validation:attempt"),
        )
        for command in attempt.commands:
            # Preserve truncated logs as such; they cannot support confirmation.
            ref = command.log
            data = read_local(output, ref.path, LIMIT)
            if (
                ref.sha256 != hashlib.sha256(data).hexdigest()
                or ref.size_bytes != len(data)
                or ref.truncated
            ):
                integrity = False
            artifacts.append(ref)
        try:
            if (
                verify_capture(capture) != provenance
                or create_plans(capture, analysis, correlation) != document
                or read_local(plan.parent, plan.name, LIMIT) != plan_data
                or read_local(preparation.parent, preparation.name, LIMIT) != prepared_data
                or (scan is not None and verify_scan(scan) != association)
            ):
                integrity = False
        except ValueError, OSError:
            integrity = False
        result, reason = classification(
            attempt, source_verified=association is not None, integrity=integrity
        )
    else:
        result = (
            "unsupported"
            if original.status == "unsupported_mapping"
            else "failed"
            if original.status == "analysis_failed"
            else "inconclusive"
        )
    observed = attempt is not None and attempt.driver is not None and attempt.driver.observed
    outcome: Literal["completed", "failed", "not_run"] = (
        "not_run"
        if attempt is None
        else "completed"
        if attempt.execution == "completed"
        else "failed"
    )
    execution = ExecutionEvidence(
        id="validation:execution",
        finding_id=finding.id,
        source=binding,
        outcome=outcome,
        oracle="observed"
        if observed
        else "not_observed"
        if attempt and attempt.driver and attempt.driver.outcome == "completed"
        else "not_evaluated",
        oracle_id="cwe22-fresh-canary-v1" if attempt and attempt.driver else None,
        image_id=attempt.image.image_id if attempt else None,
        static_evidence_id=static.id if selected_path else None,
        static_path_id=selected_path.id if selected_path else None,
        reasons=tuple(attempt.reasons) + (reason,) if attempt else (reason,),
        artifact_ids=execution_refs,
    )
    bundle = EvidenceBundle(
        schema_version="1.0",
        finding=finding,
        snapshots=snapshots,
        static_evidence=(static,),
        execution_evidence=(execution,),
        artifacts=tuple(artifacts),
        assessment=Assessment(
            classification=result,
            reasons=(reason,),
            static_evidence_id=static.id,
            static_path_id=selected_path.id if selected_path else None,
            execution_evidence_id=execution.id,
        ),
    )
    content = bundle.model_dump_json(indent=2) + "\n"
    if len(content.encode()) > LIMIT:
        raise RunnerFailure("result_limit", "Assembled evidence exceeds 64 MiB")
    publish(output / "result.json", content)
    if interrupted:
        raise KeyboardInterrupt
    return bundle
