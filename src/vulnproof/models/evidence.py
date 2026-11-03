"""Finding, static-analysis, and execution observations, independent of verdicts."""

from typing import Literal, Self

from pydantic import Field, model_validator

from .common import (
    Contract,
    CweId,
    Identifier,
    ImageId,
    Reason,
    SourceBinding,
    SourceLocation,
    Text,
    ToolIdentity,
)


class Finding(Contract):
    id: Identifier
    scanner: ToolIdentity
    rule_id: Text
    original_ref: Text | None = None
    cwes: tuple[CweId, ...] = ()
    location: SourceLocation
    source: SourceBinding
    artifact_ids: tuple[Identifier, ...] = ()


class StaticPath(Contract):
    id: Identifier
    locations: tuple[SourceLocation, ...] = Field(min_length=2)


class StaticEvidence(Contract):
    id: Identifier
    finding_id: Identifier
    tool: ToolIdentity
    rule_id: Text | None = None
    cwe: CweId | None = None
    source: SourceBinding
    outcome: Literal["path_found", "no_path_found", "unsupported", "failed", "not_run"]
    paths: tuple[StaticPath, ...] = ()
    reasons: tuple[Reason, ...] = ()
    artifact_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def path_state(self) -> Self:
        if (self.outcome == "path_found") != bool(self.paths):
            raise ValueError(
                "path_found requires paths; other outcomes cannot claim complete paths"
            )
        if self.outcome != "path_found" and not self.reasons:
            raise ValueError("non-path static outcomes require reasons")
        return self


class ExecutionEvidence(Contract):
    id: Identifier
    finding_id: Identifier
    source: SourceBinding
    outcome: Literal["completed", "failed", "not_run"]
    oracle: Literal["observed", "not_observed", "not_evaluated"] = "not_evaluated"
    oracle_id: Identifier | None = None
    image_id: ImageId | None = None
    static_evidence_id: Identifier | None = None
    static_path_id: Identifier | None = None
    reasons: tuple[Reason, ...] = ()
    artifact_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def execution_state(self) -> Self:
        if (self.static_evidence_id is None) != (self.static_path_id is None):
            raise ValueError("static evidence and path references must be supplied together")
        if self.outcome == "not_run" and self.oracle != "not_evaluated":
            raise ValueError("a test that did not run cannot claim an oracle observation")
        if self.oracle != "not_evaluated" and self.oracle_id is None:
            raise ValueError("evaluated observations require an oracle identifier")
        if self.oracle == "observed" and not self.artifact_ids:
            raise ValueError("positive observations require supporting artifact references")
        if self.outcome != "completed" and not self.reasons:
            raise ValueError("failed/not-run execution requires reasons")
        return self
