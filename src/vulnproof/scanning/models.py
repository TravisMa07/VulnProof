"""Controlled-scan receipts and derived source associations; no assessments."""

from typing import Literal, Self

from pydantic import Field, model_validator

from vulnproof.models import Artifact, Finding, SourceSnapshot, ToolIdentity
from vulnproof.models.common import Contract, Identifier, Reason, Sha256
from vulnproof.provenance.models import CapturedFile, fingerprint

VERSION = "1.184.0"
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_SARIF_BYTES = 10 * 1024 * 1024
MAX_LOG_BYTES = 1024 * 1024


class ScanProfile(Contract):
    schema_version: Literal["1.0"]
    id: Literal["fixture-semgrep-v1"]
    version: Literal["1.184.0"]
    lock_sha256: Sha256


class ToolPreparation(Contract):
    schema_version: Literal["1.0"]
    profile: Literal["fixture-semgrep-v1"]
    version: Literal["1.184.0"]
    python: Literal["3.14"]
    uv: Literal["0.13.6"]
    lock_sha256: Sha256


class ScanCommand(Contract):
    stage: Literal["version", "scan"]
    outcome: Literal[
        "completed", "failed", "timed_out", "output_limit", "interrupted", "start_failed"
    ]
    return_code: int | None
    stdout: Artifact
    stderr: Artifact


class ScanReceipt(Contract):
    schema_version: Literal["1.0"]
    profile: Literal["fixture-semgrep-v1"]
    id: Identifier
    fixture_id: Identifier
    source_fingerprint: Sha256
    scanned_files: tuple[CapturedFile, ...]
    profile_sha256: Sha256
    rule_id: Literal["vulnproof.fixture.cwe22.file-read"]
    rule_sha256: Sha256
    tool_preparation: Artifact
    scanner: ToolIdentity | None = None
    outcome: Literal["completed", "failed"]
    snapshot: SourceSnapshot | None = None
    raw_sarif: Artifact | None = None
    ingestion: Artifact | None = None
    provenance: Artifact | None = None
    commands: tuple[ScanCommand, ...]
    reasons: tuple[Reason, ...]

    @model_validator(mode="after")
    def completed_scan(self) -> Self:
        if fingerprint(self.scanned_files) != self.source_fingerprint:
            raise ValueError("scan fingerprint disagrees with manifest")
        if self.outcome == "completed":
            if (
                self.snapshot is None
                or self.snapshot.fingerprint != self.source_fingerprint
                or self.scanner is None
                or self.scanner.version != VERSION
                or self.raw_sarif is None
                or self.provenance is None
                or self.ingestion is None
                or tuple(c.stage for c in self.commands) != ("version", "scan")
                or any(c.outcome != "completed" or c.return_code != 0 for c in self.commands)
            ):
                raise ValueError(
                    "completed scan requires a source-bound capture and successful pinned scan"
                )
            artifacts = (
                self.tool_preparation,
                self.raw_sarif,
                self.ingestion,
                self.provenance,
                *(a for c in self.commands for a in (c.stdout, c.stderr)),
            )
            if any(a.sha256 is None or a.truncated is not False for a in artifacts):
                raise ValueError("completed scan requires complete hashed artifacts")
        elif not self.reasons or self.snapshot is not None:
            raise ValueError("failed scan cannot establish matched source association")
        return self


class AssociatedFinding(Contract):
    original: Finding
    bound: Finding

    @model_validator(mode="after")
    def derived_binding_only(self) -> Self:
        if (
            self.original.source.state != "unverified"
            or self.bound.source.state != "matched"
            or self.original.model_dump(exclude={"source"})
            != self.bound.model_dump(exclude={"source"})
        ):
            raise ValueError(
                "derived finding must preserve the original occurrence except its source binding"
            )
        return self


class VerifiedScan(Contract):
    schema_version: Literal["1.0"]
    receipt_sha256: Sha256
    ingestion_sha256: Sha256
    sarif_sha256: Sha256
    snapshot: SourceSnapshot
    proof_artifacts: tuple[Artifact, ...] = Field(min_length=1)
    findings: tuple[AssociatedFinding, ...]

    @model_validator(mode="after")
    def verified_target(self) -> Self:
        ids = [f.original.id for f in self.findings]
        if len(ids) != len(set(ids)) or any(
            f.bound.source.expected_snapshot_id != self.snapshot.id
            or f.bound.source.observed_snapshot_id != self.snapshot.id
            for f in self.findings
        ):
            raise ValueError("derived occurrences must uniquely reference the verified capture")
        return self
