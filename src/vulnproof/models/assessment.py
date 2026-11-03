"""One versioned finding assessment and its self-contained reference graph."""

from typing import Literal, Self

from pydantic import Field, model_validator

from .common import Artifact, Contract, Identifier, Reason, SourceBinding, SourceSnapshot
from .evidence import ExecutionEvidence, Finding, StaticEvidence


class Assessment(Contract):
    classification: Literal["confirmed", "inconclusive", "unsupported", "failed"]
    reasons: tuple[Reason, ...] = Field(min_length=1)
    static_evidence_id: Identifier | None = None
    static_path_id: Identifier | None = None
    execution_evidence_id: Identifier | None = None

    @model_validator(mode="after")
    def paired_path_reference(self) -> Self:
        # A static failure/no-path observation may be referenced without a path.
        if self.static_path_id is not None and self.static_evidence_id is None:
            raise ValueError("a selected path requires its static evidence reference")
        return self


class EvidenceBundle(Contract):
    schema_version: Literal["1.0"]
    finding: Finding
    snapshots: tuple[SourceSnapshot, ...] = Field(min_length=1)
    static_evidence: tuple[StaticEvidence, ...] = ()
    execution_evidence: tuple[ExecutionEvidence, ...] = ()
    artifacts: tuple[Artifact, ...] = ()
    assessment: Assessment | None = None

    @model_validator(mode="after")
    def consistent_graph(self) -> Self:
        identifiers = (
            [self.finding.id]
            + [item.id for item in self.snapshots]
            + [item.id for item in self.static_evidence]
            + [path.id for item in self.static_evidence for path in item.paths]
            + [item.id for item in self.execution_evidence]
            + [item.id for item in self.artifacts]
        )
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("record identifiers must be unique within the bundle")
        snapshots = {item.id: item for item in self.snapshots}
        statics = {item.id: item for item in self.static_evidence}
        executions = {item.id: item for item in self.execution_evidence}
        artifacts = {item.id: item for item in self.artifacts}
        expected = self.finding.source.expected_snapshot_id

        def binding_matches(binding: SourceBinding) -> None:
            if binding.expected_snapshot_id != expected:
                raise ValueError("evidence must name the finding's expected snapshot")
            if expected not in snapshots:
                raise ValueError("unknown expected snapshot reference")
            observed_id = binding.observed_snapshot_id
            if observed_id is not None and observed_id not in snapshots:
                raise ValueError("unknown observed snapshot reference")
            if binding.state == "unverified":
                return
            assert observed_id is not None
            left, right = snapshots[expected], snapshots[observed_id]
            if left.fingerprint is None or right.fingerprint is None:
                raise ValueError("matched/mismatched bindings require content fingerprints")
            equal = left.fingerprint == right.fingerprint
            if (binding.state == "matched") != equal:
                raise ValueError("binding state contradicts the content fingerprints")
            if equal:
                left_files = {item.path: item.sha256 for item in left.files}
                for item in right.files:
                    if item.path in left_files and left_files[item.path] != item.sha256:
                        raise ValueError("equal snapshot fingerprints have conflicting file hashes")

        records: tuple[Finding | StaticEvidence | ExecutionEvidence, ...] = (
            self.finding,
            *self.static_evidence,
            *self.execution_evidence,
        )
        for record in records:
            binding_matches(record.source)
            if isinstance(record, (StaticEvidence, ExecutionEvidence)):
                if record.finding_id != self.finding.id:
                    raise ValueError("evidence references a different finding")
            if any(reference not in artifacts for reference in record.artifact_ids):
                raise ValueError("unknown artifact reference")

        for attempt in self.execution_evidence:
            if attempt.static_evidence_id is not None:
                static = statics.get(attempt.static_evidence_id)
                if static is None or attempt.static_path_id not in {p.id for p in static.paths}:
                    raise ValueError("execution references an unknown static evidence/path pair")

        selected = self.assessment
        if selected is None:
            return self
        static = None
        if selected.static_evidence_id is not None:
            static = statics.get(selected.static_evidence_id)
            if static is None:
                raise ValueError("assessment references unknown static evidence")
            if selected.static_path_id is not None:
                if selected.static_path_id not in {path.id for path in static.paths}:
                    raise ValueError("assessment references a path from different static evidence")
        execution = None
        if selected.execution_evidence_id is not None:
            execution = executions.get(selected.execution_evidence_id)
            if execution is None:
                raise ValueError("assessment references unknown execution evidence")

        if selected.classification == "confirmed":
            if static is None or static.outcome != "path_found" or selected.static_path_id is None:
                raise ValueError("confirmation requires a selected static path")
            if (
                execution is None
                or execution.outcome != "completed"
                or execution.oracle != "observed"
            ):
                raise ValueError("confirmation requires completed execution and a positive oracle")
            if execution.image_id is None:
                raise ValueError("v0.1 confirmation requires the executed immutable image ID")
            if (
                execution.static_evidence_id != static.id
                or execution.static_path_id != selected.static_path_id
            ):
                raise ValueError("confirmation must select the path targeted by the execution")
            if any(
                record.source.state != "matched" for record in (self.finding, static, execution)
            ):
                raise ValueError(
                    "confirmation requires matched provenance for finding and evidence"
                )
            if static.cwe is None or static.cwe not in self.finding.cwes:
                raise ValueError("confirmation requires a shared declared CWE")
            path = next(path for path in static.paths if path.id == selected.static_path_id)
            if not path.locations[-1].overlaps(self.finding.location):
                raise ValueError("selected sink does not overlap the finding location")
            if not any(
                artifacts[ref].truncated is False and artifacts[ref].sha256 is not None
                for ref in execution.artifact_ids
            ):
                raise ValueError("confirmation requires a complete, hashed supporting artifact")
        return self
