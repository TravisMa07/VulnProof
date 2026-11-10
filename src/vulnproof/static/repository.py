"""Investigate the retained repository snapshot using the pinned Python path query."""

import hashlib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from vulnproof.artifacts import read_local
from vulnproof.models import Artifact, Reason, ToolIdentity
from vulnproof.models.common import Contract, Sha256, relative_path
from vulnproof.provenance.filesystem import open_root, scan_tree
from vulnproof.provenance.models import MAX_FILES, CapturedFile, fingerprint
from vulnproof.runner.engine import publish

from .analysis import _environment, check_bundle, query_source
from .models import MAX_SARIF_BYTES, QUERY_ID, QUERY_SHA256, CommandRecord, QueryResult
from .process import AnalysisFailure, artifact
from .sarif import normalize_sarif


class ScanInput(BaseModel):
    schema_version: Literal["1.0"]
    profile: Literal["repository-scan-v1", "repository-import-v1"]
    outcome: Literal["completed", "partial", "no_applicable_targets"]
    component: str | None
    files: tuple[CapturedFile, ...] = Field(max_length=MAX_FILES)
    source_fingerprint: Sha256


class Investigation(Contract):
    model_config = ConfigDict(frozen=False, validate_assignment=True)
    schema_version: Literal["1.0"] = "1.0"
    scan_sha256: Sha256
    source_fingerprint: Sha256
    component: str | None
    query_id: Literal["py/path-injection"] = QUERY_ID
    query_sha256: Sha256 = QUERY_SHA256
    tool: ToolIdentity | None = None
    outcome: Literal["completed", "partial", "unsupported", "failed"] = "failed"
    results: tuple[QueryResult, ...] = ()
    commands: tuple[CommandRecord, ...] = ()
    raw_sarif: Artifact | None = None
    diagnostics: tuple[Reason, ...] = ()


def investigate(scan: Path, output: Path, bundle: Path) -> Investigation:
    scan, output, bundle = scan.absolute(), output.absolute(), bundle.resolve()
    if any(
        a.resolve().is_relative_to(b.resolve())
        for a, b in ((output, scan), (bundle, scan), (output, bundle), (scan, bundle))
    ):
        raise AnalysisFailure(
            "invalid_workspace", "Select separate scan, output and tool directories"
        )
    try:
        receipt = read_local(scan, "scan.json", 16 * 1024 * 1024)
        selected = ScanInput.model_validate_json(receipt)
        if selected.component is not None:
            relative_path(selected.component)
            if any(not f.path.startswith(selected.component + "/") for f in selected.files):
                raise ValueError("File outside component")
        if fingerprint(selected.files) != selected.source_fingerprint:
            raise ValueError("Manifest fingerprint mismatch")
    except ValueError as exc:
        raise AnalysisFailure(
            "invalid_scan", "Expected a repository scan with a consistent manifest"
        ) from exc
    output.mkdir(mode=0o700)
    (output / "diagnostics").mkdir()
    work = output / "work"
    source = work / "source"
    source.mkdir(parents=True)
    report = Investigation(
        scan_sha256=hashlib.sha256(receipt).hexdigest(),
        source_fingerprint=selected.source_fingerprint,
        component=selected.component,
    )
    records: list[CommandRecord] = []
    try:
        with open_root(scan / "snapshot") as fd:
            copied = scan_tree(fd, source)
        if copied.files != selected.files or copied.excluded_paths:
            raise AnalysisFailure(
                "source_changed", "Snapshot differs from repository scan manifest"
            )
        if not any(f.path.endswith(".py") for f in copied.files):
            report.outcome = "unsupported"
            report.diagnostics = (
                Reason(
                    code="no_python_source",
                    message="No captured Python files for the selected query",
                ),
            )
        else:
            env = _environment(work, bundle)
            report.tool = check_bundle(bundle, output, env, records)
            sarif = query_source(bundle, output, env, records)
            with open_root(source) as fd:
                after = scan_tree(fd)
            if after.files != copied.files or after.excluded_paths:
                raise AnalysisFailure(
                    "source_changed", "Private analysis copy changed during extraction"
                )
            report.results, report.diagnostics = normalize_sarif(
                sarif.read_bytes(), source, copied.files
            )
            report.outcome = (
                "partial"
                if report.diagnostics or any(r.diagnostics for r in report.results)
                else "completed"
            )
    except (OSError, ValueError) as exc:
        report.diagnostics = (
            Reason(
                code=getattr(exc, "code", "analysis_failed"),
                message=str(exc)
                if isinstance(exc, AnalysisFailure)
                else "Source verification or tool operation failed",
            ),
        )
    except KeyboardInterrupt:
        report.diagnostics = (
            Reason(code="analysis_interrupted", message="CodeQL investigation interrupted"),
        )
        raise
    finally:
        raw = output / "diagnostics/raw.sarif"
        if raw.is_file():
            oversized = raw.stat().st_size > MAX_SARIF_BYTES
            if oversized:
                with raw.open("r+b") as stream:
                    stream.truncate(MAX_SARIF_BYTES)
            report.raw_sarif = artifact(raw, output, "sarif:raw", truncated=oversized)
        report.commands = tuple(records)
        publish(output / "investigation.json", report.model_dump_json(indent=2) + "\n")
    return report
