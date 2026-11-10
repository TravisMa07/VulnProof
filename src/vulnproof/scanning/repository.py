"""Run the reviewed repository rules on a local, bounded checkout snapshot."""

import hashlib
import json
import os
from dataclasses import asdict
from importlib.resources import files
from pathlib import Path

from vulnproof.artifacts import read_local
from vulnproof.intake import Inventory, inventory
from vulnproof.models.common import relative_path
from vulnproof.provenance.filesystem import excluded, open_root, scan_tree
from vulnproof.provenance.git import checkout_head
from vulnproof.provenance.models import CapturedFile, fingerprint

from .engine import scan_profile, scanner_environment
from .models import MAX_DOCUMENT_BYTES, MAX_SARIF_BYTES, VERSION, ScanCommand, ToolPreparation
from .process import ScanFailure, command

SUFFIXES = {".py", ".js"}


def scanned_paths(output: Path) -> tuple[set[str], bool]:
    coverage = json.loads(read_local(output, "diagnostics/semgrep.json", MAX_SARIF_BYTES))
    paths = coverage.get("paths") if isinstance(coverage, dict) else None
    scanned = paths.get("scanned") if isinstance(paths, dict) else None
    if not isinstance(scanned, list) or not all(isinstance(p, str) for p in scanned):
        raise ScanFailure("invalid_coverage", "Missing Semgrep target accounting")
    return {p.removeprefix("./") for p in scanned}, coverage.get("errors") != []


def successful_invocation(inv: Inventory) -> bool:
    invocations = json.loads(inv.raw_sarif)["runs"][0].get("invocations")
    return (
        isinstance(invocations, list)
        and len(invocations) == 1
        and isinstance(invocations[0], dict)
        and invocations[0].get("executionSuccessful") is True
        and invocations[0].get("toolExecutionNotifications") == []
    )


def capture_repository(
    repo: Path, component: str | None, output: Path
) -> tuple[tuple[CapturedFile, ...], list[str]]:
    if output.resolve().is_relative_to(repo.resolve()):
        raise ScanFailure("invalid_layout", "Output must be outside checkout")
    if component is not None:
        try:
            relative_path(component)
        except ValueError as exc:
            raise ScanFailure(
                "invalid_component", "Expected a repository-relative directory"
            ) from exc
        if excluded(component):
            raise ScanFailure("excluded_component", "Component is excluded from capture")
    selected = repo / (component or "")
    snapshot = output / "snapshot"
    with open_root(selected) as descriptor:
        output.mkdir(mode=0o700)
        destination = snapshot / (component or "")
        destination.mkdir(parents=True)
        tree = scan_tree(descriptor, destination)
    manifest = tuple(
        f.model_copy(update={"path": str(Path(component or "") / f.path)}) for f in tree.files
    )
    return manifest, [str(Path(component or "") / p) for p in tree.excluded_paths]


def scan_repository(repo: Path, component: str | None, output: Path, environment: Path) -> str:
    repo, output, environment = repo.absolute(), output.absolute(), environment.absolute()
    if any(
        a.resolve().is_relative_to(b.resolve())
        for a, b in (
            (output, repo),
            (environment, repo),
            (repo, environment),
            (output, environment),
            (environment, output),
        )
    ):
        raise ScanFailure("invalid_layout", "Keep checkout, tool installation and output separate")
    try:
        prepared = ToolPreparation.model_validate_json(
            read_local(environment, "prepared.json", MAX_DOCUMENT_BYTES)
        )
    except (OSError, ValueError) as exc:
        raise ScanFailure(
            "unprepared_scanner", "Prepare the pinned Semgrep environment first"
        ) from exc
    if prepared.lock_sha256 != scan_profile().lock_sha256:
        raise ScanFailure("stale_scanner", "Prepare Semgrep with the current tool lock")
    manifest, exclusions = capture_repository(repo, component, output)
    snapshot = output / "snapshot"
    work = output / "work"
    targets = work / "source"
    for directory in (
        "diagnostics",
        "work/source",
        "work/home",
        "work/tmp",
        "work/config",
        "work/cache",
    ):
        (output / directory).mkdir(parents=True)
    eligible = tuple(f for f in manifest if Path(f.path).suffix in SUFFIXES)
    for entry in eligible:
        target = targets / entry.path
        target.parent.mkdir(parents=True, exist_ok=True)
        os.link(snapshot / entry.path, target)
    rules = files("vulnproof.scanning").joinpath("repository.yaml").read_bytes()
    (work / "rules.yaml").write_bytes(rules)
    records: list[ScanCommand] = []
    env = scanner_environment(output, environment)
    executable = str(environment / "bin/semgrep")
    coverage_path = output / "diagnostics/semgrep.json"
    raw_path = output / "diagnostics/raw.sarif"
    receipt: dict[str, object] = {
        "schema_version": "1.0",
        "profile": "repository-scan-v1",
        "semgrep_version": VERSION,
        "tool_lock_sha256": prepared.lock_sha256,
        "rules_sha256": hashlib.sha256(rules).hexdigest(),
        "component": component,
        "observed_checkout_head": checkout_head(repo),
        "source_fingerprint": fingerprint(manifest),
        "files": [f.model_dump() for f in manifest],
        "excluded_paths": exclusions,
        "target_paths": [f.path for f in eligible],
        "outcome": "failed",
    }
    try:
        version = command(
            [executable, "--version", "--disable-version-check"],
            stage="version",
            root=output,
            env=env,
            records=records,
            timeout=30,
        )
        if version.decode().strip() != VERSION:
            raise ScanFailure("scanner_version", "Prepared scanner version differs from pin")
        args = [
            executable,
            "scan",
            "--config",
            str(work / "rules.yaml"),
            "--oss-only",
            "--metrics=off",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--no-git-ignore",
            "--disable-nosem",
            "--jobs=1",
            "--timeout=10",
            "--max-memory=512",
            "--max-target-bytes=8388608",
            "--json-output",
            str(coverage_path),
            "--sarif",
            "--output",
            str(raw_path),
        ]
        command(
            [*args, *(["./" + f.path for f in eligible] or ["."])],
            stage="scan",
            root=output,
            env=env,
            records=records,
            timeout=120,
            sarif=raw_path,
            coverage=coverage_path,
        )
        with open_root(targets) as descriptor:
            if scan_tree(descriptor).files != eligible:
                raise ScanFailure("source_changed", "Scanner inputs changed during scan")
        raw = read_local(output, "diagnostics/raw.sarif", MAX_SARIF_BYTES)
        inv = inventory(raw, snapshot, component)
        inv.checkout_head = None  # A private byte snapshot has no asserted Git revision.
        if (
            len(inv.runs) != 1
            or inv.runs[0].scanner != "Semgrep OSS"
            or inv.runs[0].version != VERSION
        ):
            raise ScanFailure("invalid_scan_report", "Expected one run from the pinned scanner")
        actual, errors = scanned_paths(output)
        expected = {f.path for f in eligible}
        if actual - expected:
            raise ScanFailure("unexpected_target", "Semgrep reported an unselected target")
        receipt["scanned_paths"] = sorted(actual)
        receipt["unscanned_targets"] = sorted(expected - actual)
        content = json.dumps(asdict(inv), indent=2) + "\n"
        if len(content.encode()) > MAX_DOCUMENT_BYTES:
            raise ScanFailure("inventory_limit", "Inventory exceeds 64 MiB")
        (output / "inventory.json").write_text(content, encoding="utf-8")
        outcome = "completed" if eligible else "no_applicable_targets"
        if (
            errors
            or actual != expected
            or inv.status == "partial"
            or not successful_invocation(inv)
        ):
            outcome = "partial"
        receipt.update(
            outcome=outcome, sarif_sha256=inv.input_sha256, result_count=inv.result_count
        )
        return outcome
    except (ValueError, OSError) as exc:
        receipt["reason"] = getattr(exc, "code", "scan_failed")
        raise ScanFailure(
            str(receipt["reason"]), "Repository scan failed; see scan.json and diagnostics"
        ) from exc
    finally:
        for path in (raw_path, coverage_path):
            if path.exists() and path.stat().st_size > MAX_SARIF_BYTES:
                with path.open("r+b") as stream:
                    stream.truncate(MAX_SARIF_BYTES)
                receipt[path.name + "_truncated"] = True
        receipt["commands"] = [r.model_dump() for r in records]
        (output / "scan.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
