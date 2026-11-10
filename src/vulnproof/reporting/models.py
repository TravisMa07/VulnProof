"""Report observations preserve the original evidence and its recorded assessment."""

from typing import Literal, Self

from pydantic import Field, model_validator

from vulnproof.models import Artifact, EvidenceBundle, Reason
from vulnproof.models.common import Contract, Identifier, Sha256
from vulnproof.validation.models import Attempt

Integrity = Literal["verified", "incomplete", "failed"]
ArtifactStatus = Literal[
    "verified", "incomplete", "missing", "changed", "unreadable", "limit_exceeded"
]


class ArtifactCheck(Contract):
    artifact: Artifact
    status: ArtifactStatus
    observed_sha256: Sha256 | None = None
    observed_size_bytes: int | None = Field(default=None, ge=0)
    preview_encoding: Literal["utf-8", "base64", "none"] = "none"
    preview: str = Field(default="", max_length=21848)
    preview_truncated: bool = False
    reasons: tuple[Reason, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def observation(self) -> Self:
        read = self.status in ("verified", "incomplete", "changed")
        if read != (self.observed_sha256 is not None and self.observed_size_bytes is not None):
            raise ValueError("read status requires observed hash and size")
        if self.status == "verified" and (
            self.artifact.sha256 != self.observed_sha256
            or self.artifact.size_bytes != self.observed_size_bytes
            or self.artifact.truncated is not False
        ):
            raise ValueError("verified artifact requires complete matching metadata")
        if self.preview_encoding == "none" and self.preview:
            raise ValueError("absent preview cannot contain text")
        return self


class RuntimeDetail(Contract):
    execution_id: Identifier
    artifact_id: Identifier | None
    status: Literal["available", "unavailable", "invalid"]
    attempt: Attempt | None = None
    reason: Reason

    @model_validator(mode="after")
    def available(self) -> Self:
        if (self.status == "available") != (self.attempt is not None):
            raise ValueError("only available details can carry a parsed attempt")
        return self


def integrity_state(checks: tuple[ArtifactCheck, ...]) -> Integrity:
    if any(c.status in ("changed", "unreadable") for c in checks):
        return "failed"
    if not checks or any(c.status != "verified" for c in checks):
        return "incomplete"
    return "verified"


class ReportDocument(Contract):
    schema_version: Literal["1.0"]
    profile: Literal["single-validation-report-v1"]
    result_sha256: Sha256
    evidence: EvidenceBundle
    integrity: Integrity
    artifacts: tuple[ArtifactCheck, ...]
    runtime: tuple[RuntimeDetail, ...]
    warnings: tuple[Reason, ...]

    @model_validator(mode="after")
    def references(self) -> Self:
        if tuple(c.artifact for c in self.artifacts) != self.evidence.artifacts:
            raise ValueError("report must retain every artifact in the original order")
        if self.integrity != integrity_state(self.artifacts):
            raise ValueError("integrity disagrees with artifact observations")
        if tuple(d.execution_id for d in self.runtime) != tuple(
            e.id for e in self.evidence.execution_evidence
        ):
            raise ValueError("runtime details must retain every execution")
        return self
