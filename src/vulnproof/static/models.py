"""Analysis observations deliberately have no Semgrep finding association."""

from typing import Literal, Self

from pydantic import Field, model_validator

from vulnproof.investigation.query_policy import PACK_VERSION as PACK_VERSION
from vulnproof.investigation.query_policy import QUERY_ID as QUERY_ID
from vulnproof.investigation.query_policy import QUERY_RELATIVE as QUERY_RELATIVE
from vulnproof.investigation.query_policy import QUERY_SHA256 as QUERY_SHA256
from vulnproof.models import (
    Artifact,
    Reason,
    SourceBinding,
    SourceLocation,
    SourceSnapshot,
    StaticPath,
    ToolIdentity,
)
from vulnproof.models.common import Contract, Identifier, NonNegative, Sha256, Text

CODEQL_VERSION = "2.27.3"
MAX_LOG_BYTES = 1024 * 1024
MAX_SARIF_BYTES = 10 * 1024 * 1024


class Fixture(Contract):
    id: Identifier
    fingerprint: Sha256
    description: Text


class FixtureManifest(Contract):
    schema_version: Literal["1.0"]
    fixtures: tuple[Fixture, ...]

    @model_validator(mode="after")
    def unique_approvals(self) -> Self:
        if len({f.id for f in self.fixtures}) != len(self.fixtures) or len(
            {f.fingerprint for f in self.fixtures}
        ) != len(self.fixtures):
            raise ValueError("fixture approvals must be unique")
        return self


class AnalysisPath(Contract):
    original_ref: Text
    path: StaticPath


class QueryResult(Contract):
    id: Identifier
    original_ref: Text
    sink: SourceLocation | None = None
    paths: tuple[AnalysisPath, ...] = ()
    observed_paths: NonNegative = 0
    diagnostics: tuple[Reason, ...] = ()

    @model_validator(mode="after")
    def paths_accounted_for(self) -> Self:
        if len(self.paths) > self.observed_paths:
            raise ValueError("normalized path count exceeds observed paths")
        if self.paths and (
            self.sink is None
            or any(not p.path.locations[-1].overlaps(self.sink) for p in self.paths)
        ):
            raise ValueError("normalized paths require a compatible result sink")
        return self


class CommandRecord(Contract):
    stage: Literal["version", "extract", "query"]
    outcome: Literal[
        "completed", "nonzero_exit", "timed_out", "output_limit", "interrupted", "start_failed"
    ]
    return_code: int | None = None
    duration_seconds: float = Field(ge=0)
    log: Artifact


class AnalysisDocument(Contract):
    schema_version: Literal["1.0"]
    id: Identifier
    fixture_id: Identifier
    snapshot: SourceSnapshot
    source: SourceBinding
    tool: ToolIdentity | None = None
    query_id: Literal["py/path-injection"] = QUERY_ID
    query_pack: Literal["codeql/python-queries@1.8.13"] = "codeql/python-queries@1.8.13"
    query_sha256: Sha256 = QUERY_SHA256
    threads: Literal[2] = 2
    ram_mb: Literal[2048] = 2048
    max_paths_per_result: Literal[4] = 4
    outcome: Literal["completed", "failed"]
    normalization: Literal["complete", "partial", "not_attempted"]
    results: tuple[QueryResult, ...] = ()
    commands: tuple[CommandRecord, ...] = ()
    raw_sarif: Artifact | None = None
    diagnostics: tuple[Reason, ...] = ()

    @model_validator(mode="after")
    def consistent_run(self) -> Self:
        if self.query_sha256 != QUERY_SHA256:
            raise ValueError("analysis profile must name the pinned query hash")
        if self.source.expected_snapshot_id != self.snapshot.id:
            raise ValueError("analysis must reference its captured target")
        if self.outcome == "completed":
            if (
                self.source.state != "matched"
                or self.source.observed_snapshot_id != self.snapshot.id
                or self.snapshot.fingerprint is None
            ):
                raise ValueError("completed analysis requires verified analysis-source association")
            if (
                self.raw_sarif is None
                or self.raw_sarif.truncated is not False
                or self.raw_sarif.sha256 is None
            ):
                raise ValueError("completed analysis requires complete hashed SARIF")
            if self.tool != ToolIdentity(
                name="CodeQL",
                version=CODEQL_VERSION,
                rule_pack="codeql/python-queries@" + PACK_VERSION,
            ):
                raise ValueError("completed analysis requires the pinned tool identity")
            if tuple(c.stage for c in self.commands) != ("version", "extract", "query") or any(
                c.outcome != "completed"
                or c.return_code != 0
                or c.log.truncated is not False
                or c.log.sha256 is None
                for c in self.commands
            ):
                raise ValueError("completed analysis requires all successful command stages")
            partial = any(r.diagnostics for r in self.results) or bool(self.diagnostics)
            if self.normalization != ("partial" if partial else "complete"):
                raise ValueError("normalization state disagrees with diagnostics")
        elif (
            not self.diagnostics
            or self.results
            or self.normalization != "not_attempted"
            or self.source.state != "unverified"
        ):
            raise ValueError("failed analysis cannot claim usable results or matched source")
        ids = [r.id for r in self.results] + [p.path.id for r in self.results for p in r.paths]
        if len(ids) != len(set(ids)):
            raise ValueError("analysis result/path identifiers must be unique")
        return self
