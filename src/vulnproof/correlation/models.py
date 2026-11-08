"""Candidate relationships are observations, never exploitability assessments."""

from typing import Literal, Self

from pydantic import Field, model_validator

from vulnproof.ingest.models import ImportedFinding
from vulnproof.models import Reason, SourceSnapshot
from vulnproof.models.common import Contract, Identifier, Sha256
from vulnproof.static.models import QueryResult


class CompatibilityPolicy(Contract):
    id: Literal["fixture-cwe22-v1"] = "fixture-cwe22-v1"
    rule_id: Literal["vulnproof.fixture.cwe22.file-read"] = "vulnproof.fixture.cwe22.file-read"
    rule_sha256: Sha256
    cwe: Literal["CWE-22"] = "CWE-22"
    sink_family: Literal["fixture-file-read"] = "fixture-file-read"
    query_id: Literal["py/path-injection"] = "py/path-injection"


class FindingCorrelation(Contract):
    imported: ImportedFinding
    scanner_source_state: Literal["unverified"] = "unverified"
    status: Literal[
        "single_candidate",
        "ambiguous",
        "no_candidate",
        "unsupported_mapping",
        "location_unavailable",
        "analysis_failed",
    ]
    candidates: tuple[QueryResult, ...] = ()
    reasons: tuple[Reason, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def consistent_candidates(self) -> Self:
        if self.imported.finding.source.state != "unverified":
            raise ValueError("correlation must preserve unverified scanner source association")
        count = len(self.candidates)
        expected = "single_candidate" if count == 1 else "ambiguous" if count > 1 else None
        if (expected is not None and self.status != expected) or (
            expected is None and self.status in ("single_candidate", "ambiguous")
        ):
            raise ValueError("candidate count disagrees with correlation status")
        if len({r.id for r in self.candidates}) != count:
            raise ValueError("candidate result identifiers must be unique")
        if any(
            not r.paths or r.sink is None or not r.sink.overlaps(self.imported.finding.location)
            for r in self.candidates
        ):
            raise ValueError("candidate requires complete paths and an overlapping sink")
        if self.candidates and (
            self.imported.finding.rule_id != "vulnproof.fixture.cwe22.file-read"
            or "CWE-22" not in self.imported.finding.cwes
        ):
            raise ValueError("candidate requires the reviewed rule/CWE mapping")
        return self


class CorrelationDocument(Contract):
    schema_version: Literal["1.0"]
    policy: CompatibilityPolicy
    snapshot: SourceSnapshot
    ingestion_sha256: Sha256
    ingestion_status: Literal["complete", "partial"]
    analysis_sha256: Sha256
    analysis_id: Identifier
    analysis_outcome: Literal["completed", "failed"]
    analysis_normalization: Literal["complete", "partial", "not_attempted"]
    raw_sarif_sha256: Sha256 | None
    findings: tuple[FindingCorrelation, ...]
    diagnostics: tuple[Reason, ...]

    @model_validator(mode="after")
    def unique_findings(self) -> Self:
        ids = [f.imported.finding.id for f in self.findings]
        if len(ids) != len(set(ids)):
            raise ValueError("finding identities must be unique")
        if self.analysis_outcome == "failed" and any(f.candidates for f in self.findings):
            raise ValueError("failed analysis cannot support candidates")
        if (self.analysis_outcome == "failed") != (self.analysis_normalization == "not_attempted"):
            raise ValueError("analysis outcome disagrees with normalization state")
        if self.analysis_outcome == "completed" and self.raw_sarif_sha256 is None:
            raise ValueError("completed analysis requires the retained SARIF hash")
        return self
