"""Versioned ingestion output; original scanner data remains in raw_sarif."""

import hashlib
from typing import Literal, Self

from pydantic import Field, model_validator

from vulnproof.models import Finding, SourceSnapshot, ToolIdentity
from vulnproof.models.common import Contract, Identifier, NonNegative, Sha256, Text


class Diagnostic(Contract):
    code: Identifier
    severity: Literal["warning", "error"]
    pointer: Text
    message: Text


class ImportedFinding(Contract):
    finding: Finding
    run_index: NonNegative
    result_index: NonNegative
    duplicate_of: Identifier | None = None
    suppression: Literal["absent", "present"]
    level: Literal["none", "note", "warning", "error"] | None = None


class ImportedRun(Contract):
    run_index: NonNegative
    scanner: ToolIdentity | None = None
    supported: bool
    result_count: NonNegative | None = None
    imported_count: NonNegative = 0
    rejected_count: NonNegative = 0
    scan_status: Literal["unknown", "reported_success", "reported_problems"] = "unknown"


class IngestionDocument(Contract):
    schema_version: Literal["1.0"]
    input_sha256: Sha256
    input_size_bytes: NonNegative
    raw_sarif: str
    runs: tuple[ImportedRun, ...]
    snapshots: tuple[SourceSnapshot, ...]
    findings: tuple[ImportedFinding, ...]
    diagnostics: tuple[Diagnostic, ...] = ()
    # This describes ingestion only. It is never a vulnerability classification.
    status: Literal["complete", "partial"]
    result_count: NonNegative = Field(description="Results in runs with readable result arrays")

    @model_validator(mode="after")
    def consistent_import(self) -> Self:
        data = self.raw_sarif.encode("utf-8")
        if (
            len(data) != self.input_size_bytes
            or hashlib.sha256(data).hexdigest() != self.input_sha256
        ):
            raise ValueError("input identity does not match retained SARIF bytes")
        runs = {run.run_index: run for run in self.runs}
        snapshots = {snapshot.id for snapshot in self.snapshots}
        if len(runs) != len(self.runs) or len(snapshots) != len(self.snapshots):
            raise ValueError("duplicate run or snapshot identity")
        seen: dict[str, ImportedFinding] = {}
        positions: set[tuple[int, int]] = set()
        counts: dict[int, int] = {}
        for item in self.findings:
            run = runs.get(item.run_index)
            if run is None or not run.supported or run.result_count is None:
                raise ValueError("finding references unsupported or unknown run")
            position = (item.run_index, item.result_index)
            if item.result_index >= run.result_count or position in positions:
                raise ValueError("invalid or duplicate result position")
            if item.finding.id in seen:
                raise ValueError("duplicate finding identity")
            source = item.finding.source
            if source.expected_snapshot_id not in snapshots or source.state != "unverified":
                raise ValueError("ingestion requires an existing, unverified source binding")
            if item.duplicate_of is not None:
                original = seen.get(item.duplicate_of)
                if original is None or original.run_index != item.run_index:
                    raise ValueError("duplicate reference must name an earlier finding in the run")
            seen[item.finding.id] = item
            positions.add(position)
            counts[item.run_index] = counts.get(item.run_index, 0) + 1
        for run in self.runs:
            if run.imported_count != counts.get(run.run_index, 0):
                raise ValueError("imported count disagrees with findings")
            if run.result_count is None:
                if run.imported_count or run.rejected_count:
                    raise ValueError("unreadable result arrays cannot claim result counts")
            elif run.result_count != run.imported_count + run.rejected_count:
                raise ValueError("run result counts disagree")
        if self.result_count != sum(run.result_count or 0 for run in self.runs):
            raise ValueError("total result count disagrees with runs")
        partial = any(item.severity == "error" for item in self.diagnostics)
        if (self.status == "partial") != partial:
            raise ValueError("import status disagrees with diagnostics")
        return self
