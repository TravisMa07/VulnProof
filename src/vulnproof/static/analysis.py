"""Pinned fixture-only CodeQL orchestration, independent of finding correlation."""

import hashlib
import json
import os
import re
import sys
from importlib.resources import files
from pathlib import Path
from uuid import uuid4

from vulnproof.investigation.capabilities import PATH_QUERY, QUERIES, QuerySpec
from vulnproof.models import Artifact, Reason, SourceBinding, ToolIdentity
from vulnproof.provenance import CaptureFailure, verify_capture
from vulnproof.provenance.filesystem import open_root, scan_tree
from vulnproof.provenance.models import fingerprint

from .models import (
    CODEQL_VERSION,
    MAX_SARIF_BYTES,
    PACK_VERSION,
    AnalysisDocument,
    CommandRecord,
    Fixture,
    FixtureManifest,
    QueryResult,
)
from .process import AnalysisFailure, artifact, run_command
from .sarif import normalize_sarif


def fixture_manifest() -> FixtureManifest:
    return FixtureManifest.model_validate_json(
        files("vulnproof.static").joinpath("fixtures.json").read_bytes()
    )


def admit_fixture(digest: str | None) -> Fixture:
    for fixture in fixture_manifest().fixtures:
        if fixture.fingerprint == digest:
            return fixture
    raise AnalysisFailure(
        "unapproved_fixture", "Capture does not match a reviewed fixture fingerprint"
    )


def _environment(work: Path, bundle: Path) -> dict[str, str]:
    # Trusted interpreter/toolchain only; no inherited Python, Java, CodeQL or auth options.
    for name in ("home", "tmp", "config", "cache"):
        (work / name).mkdir(mode=0o700)
    return {
        "PATH": str(Path(sys.executable).resolve().parent) + os.pathsep + os.defpath,
        "HOME": str(work / "home"),
        "XDG_CONFIG_HOME": str(work / "config"),
        "XDG_CACHE_HOME": str(work / "cache"),
        "TMPDIR": str(work / "tmp"),
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONPATH": str(bundle / "python" / "tools"),
        "LC_ALL": "C",
    }


def _publish_report(path: Path, report: AnalysisDocument) -> None:
    pending = path.with_suffix(".pending")
    try:
        with pending.open("x", encoding="utf-8") as stream:
            stream.write(report.model_dump_json(indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(pending, path)
    finally:
        pending.unlink(missing_ok=True)


def check_bundle(
    bundle: Path,
    output: Path,
    env: dict[str, str],
    records: list[CommandRecord],
    query_spec: QuerySpec | None = None,
) -> ToolIdentity:
    query_spec = PATH_QUERY if query_spec is None else query_spec
    executable = bundle / "codeql"
    if QUERIES.get(query_spec.id) != query_spec:
        raise AnalysisFailure("unknown_query", "Only installed query policy is accepted")
    query = bundle / query_spec.relative_path
    if not executable.is_file():
        raise AnalysisFailure(
            "codeql_missing",
            "Prepare CodeQL with scripts/prepare_codeql.py and pass its codeql directory",
        )
    version = json.loads(
        run_command(
            [str(executable), "version", "--format=json"],
            stage="version",
            root=output,
            env=env,
            timeout=30,
            records=records,
        )
    )
    if not isinstance(version, dict) or version.get("version") != CODEQL_VERSION:
        raise AnalysisFailure("codeql_version", "Expected prepared CodeQL 2.27.3")
    if (
        not query.is_file()
        or hashlib.sha256(query.read_bytes()).hexdigest() != query_spec.sha256
        or re.search(
            r"^version:\s*1\.8\.13\s*$",
            (query.parents[2] / "qlpack.yml").read_text(),
            re.MULTILINE,
        )
        is None
    ):
        raise AnalysisFailure(
            "query_mismatch", "Expected the pinned bundled official Python query and pack"
        )
    tool = ToolIdentity(
        name="CodeQL", version=CODEQL_VERSION, rule_pack="codeql/python-queries@" + PACK_VERSION
    )
    return tool


def query_source(
    bundle: Path,
    output: Path,
    env: dict[str, str],
    records: list[CommandRecord],
    query_spec: QuerySpec | None = None,
) -> Path:
    query_spec = PATH_QUERY if query_spec is None else query_spec
    executable = bundle / "codeql"
    if QUERIES.get(query_spec.id) != query_spec:
        raise AnalysisFailure("unknown_query", "Only installed query policy is accepted")
    query = bundle / query_spec.relative_path
    work = output / "work"
    source = work / "source"
    sarif = output / "diagnostics/raw.sarif"
    database = work / "database"
    run_command(
        [
            str(executable),
            "database",
            "create",
            str(database),
            "--language=python",
            "--build-mode=none",
            f"--source-root={source}",
            "--threads=2",
            "--ram=2048",
        ],
        stage="extract",
        root=output,
        env=env,
        timeout=180,
        records=records,
    )
    run_command(
        [
            str(executable),
            "database",
            "analyze",
            str(database),
            str(query),
            "--format=sarifv2.1.0",
            "--max-paths=4",
            f"--output={sarif}",
            "--threads=2",
            "--ram=2048",
        ],
        stage="query",
        root=output,
        env=env,
        timeout=300,
        records=records,
        sarif=sarif,
    )
    if not sarif.is_file() or sarif.stat().st_size > MAX_SARIF_BYTES:
        raise AnalysisFailure("sarif_limit", "CodeQL SARIF is absent or exceeds the output limit")
    return sarif


def analyze_capture(capture: Path, output: Path, bundle: Path) -> AnalysisDocument:
    """Produce an analysis report; never select builds, queries or flags from source data."""
    capture, output, bundle = (
        Path(os.path.abspath(capture)),
        Path(os.path.abspath(output)),
        bundle.resolve(),
    )
    if output.resolve().is_relative_to(capture.resolve()) or bundle.is_relative_to(
        capture.resolve()
    ):
        raise AnalysisFailure(
            "invalid_workspace", "Analysis output and tool bundle must be outside the capture"
        )
    provenance = verify_capture(capture)
    fixture = admit_fixture(provenance.snapshot.fingerprint)
    output.mkdir(mode=0o700)
    (output / "diagnostics").mkdir()
    work = output / "work"
    work.mkdir()
    env = _environment(work, bundle)
    records: list[CommandRecord] = []
    raw: Artifact | None = None
    tool: ToolIdentity | None = None
    sarif = output / "diagnostics" / "raw.sarif"
    results: tuple[QueryResult, ...] = ()
    notes: tuple[Reason, ...] = ()
    completed = False
    interrupted = False
    try:
        tool = check_bundle(bundle, output, env, records)
        source = work / "source"
        source.mkdir()
        with open_root(capture / "source") as descriptor:
            copied = scan_tree(descriptor, source)
        if (
            fingerprint(copied.files) != fixture.fingerprint
            or copied.files != provenance.files
            or copied.excluded_paths
        ):
            raise AnalysisFailure(
                "source_changed", "Copied analysis source differs from the admitted capture"
            )
        for directory, _, _ in os.walk(source, topdown=False):
            Path(directory).chmod(0o555)
        query_source(bundle, output, env, records)
        if verify_capture(capture) != provenance:
            raise AnalysisFailure("source_changed", "Input capture changed during analysis")
        with open_root(source) as descriptor:
            after = scan_tree(descriptor)
        if after.files != copied.files or after.excluded_paths:
            raise AnalysisFailure(
                "source_changed", "CodeQL analysis source changed during analysis"
            )
        results, notes = normalize_sarif(sarif.read_bytes(), source, provenance.files)
        raw = artifact(sarif, output, "sarif:raw")
        completed = True
    except KeyboardInterrupt:
        interrupted = True
        notes = (
            Reason(
                code="analysis_interrupted",
                message="Analysis interrupted; commands stopped and diagnostics retained",
            ),
        )
    except AnalysisFailure as exc:
        notes = (Reason(code=exc.code, message=str(exc)),)
    except ValueError, OSError, CaptureFailure:
        notes = (
            Reason(
                code="analysis_failed",
                message="Tool metadata, source verification, or artifact IO failed; see diagnostic logs",
            ),
        )
    finally:
        if sarif.is_file() and raw is None:
            oversized = sarif.stat().st_size > MAX_SARIF_BYTES
            if oversized:
                with sarif.open("r+b") as stream:
                    stream.truncate(MAX_SARIF_BYTES)
            raw = artifact(sarif, output, "sarif:raw", truncated=oversized)
        report = AnalysisDocument(
            schema_version="1.0",
            id="analysis:" + uuid4().hex,
            fixture_id=fixture.id,
            snapshot=provenance.snapshot,
            source=SourceBinding(
                expected_snapshot_id=provenance.snapshot.id,
                observed_snapshot_id=provenance.snapshot.id if completed else None,
                state="matched" if completed else "unverified",
                reason=Reason(
                    code="analysis_source_verified" if completed else "analysis_not_complete",
                    message="CodeQL used the verified private source copy"
                    if completed
                    else "Analysis did not establish a complete source-bound observation",
                ),
            ),
            tool=tool,
            outcome="completed" if completed else "failed",
            normalization=(
                "partial" if notes or any(r.diagnostics for r in results) else "complete"
            )
            if completed
            else "not_attempted",
            results=results if completed else (),
            commands=tuple(records),
            raw_sarif=raw,
            diagnostics=notes,
        )
        _publish_report(output / "analysis.json", report)
    if interrupted:
        raise KeyboardInterrupt
    return report
