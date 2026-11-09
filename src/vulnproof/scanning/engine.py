"""Only approved fixture bytes and the installed rule can enter a controlled scan."""

import hashlib
import os
from importlib.resources import files
from pathlib import Path
from uuid import uuid4

from vulnproof.artifacts import read_local
from vulnproof.correlation import policy
from vulnproof.ingest import IngestionDocument, ingest_sarif
from vulnproof.models import Reason
from vulnproof.provenance import CaptureFailure, capture_source, verify_capture
from vulnproof.provenance.filesystem import open_root, scan_tree
from vulnproof.provenance.models import fingerprint
from vulnproof.runner.engine import publish
from vulnproof.static import AnalysisFailure
from vulnproof.static.analysis import admit_fixture
from vulnproof.static.process import artifact

from .models import (
    MAX_DOCUMENT_BYTES,
    MAX_SARIF_BYTES,
    VERSION,
    ScanCommand,
    ScanProfile,
    ScanReceipt,
    ToolPreparation,
)
from .process import ScanFailure, command


def profile_bytes() -> bytes:
    return files("vulnproof.scanning").joinpath("profile.json").read_bytes()


def scan_profile() -> ScanProfile:
    return ScanProfile.model_validate_json(profile_bytes())


def rule_bytes() -> bytes:
    return files("vulnproof.correlation").joinpath("rules/cwe22-file-read.yaml").read_bytes()


def scan_arguments(root: Path) -> list[str]:
    return [
        "scan",
        "--config",
        str(root / "work/rule.yaml"),
        "--oss-only",
        "--metrics=off",
        "--disable-version-check",
        "--no-rewrite-rule-ids",
        "--strict",
        "--no-git-ignore",
        "--disable-nosem",
        "--jobs=1",
        "--timeout=10",
        "--max-memory=512",
        "--max-target-bytes=8388608",
        "--sarif",
        "--output",
        str(root / "diagnostics/raw.sarif"),
        "app.py",
    ]


def scanner_environment(root: Path, environment: Path) -> dict[str, str]:
    return {
        "PATH": str(environment / "bin") + os.pathsep + os.defpath,
        "HOME": str(root / "work/home"),
        "TMPDIR": str(root / "work/tmp"),
        "XDG_CONFIG_HOME": str(root / "work/config"),
        "XDG_CACHE_HOME": str(root / "work/cache"),
        "SEMGREP_SETTINGS_FILE": str(root / "work/home/settings.yml"),
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "SEMGREP_SEND_METRICS": "off",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_COUNT": "0",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CEILING_DIRECTORIES": str(root / "work"),
    }


def validate_import(raw: bytes) -> IngestionDocument:
    document = ingest_sarif(raw)
    if (
        document.status != "complete"
        or len(document.runs) != 1
        or not document.runs[0].supported
        or document.runs[0].scanner is None
        or document.runs[0].scanner.version != VERSION
        or document.runs[0].scan_status == "reported_problems"
        or any(
            f.finding.rule_id != policy().rule_id
            or "CWE-22" not in f.finding.cwes
            or f.finding.location.path != "app.py"
            for f in document.findings
        )
    ):
        raise ScanFailure(
            "invalid_scan_report",
            "Scan SARIF is incomplete or outside the pinned rule/tool profile",
        )
    return document


def scan_fixture(source: Path, output: Path, environment: Path) -> ScanReceipt:
    """Scan a private approved copy, then capture the unchanged selected original."""
    source, output, environment = source.absolute(), output.absolute(), environment.absolute()
    try:
        with open_root(source) as descriptor:
            original = scan_tree(descriptor)
        fixture = admit_fixture(fingerprint(original.files))
        profile_data = profile_bytes()
        selected_profile = ScanProfile.model_validate_json(profile_data)
        selected_rule = rule_bytes()
        marker = read_local(environment, "prepared.json", MAX_DOCUMENT_BYTES)
        prepared = ToolPreparation.model_validate_json(marker)
        if prepared.lock_sha256 != selected_profile.lock_sha256:
            raise ScanFailure(
                "stale_scanner",
                "Prepared Semgrep lock identity does not match the installed scan profile",
            )
        if (
            environment.resolve().is_relative_to(source.resolve())
            or environment.resolve().is_relative_to(output.resolve())
            or output.resolve().is_relative_to(source.resolve())
        ):
            raise ScanFailure(
                "invalid_scan_layout",
                "Tool and output must be outside selected source; tool must be outside new output",
            )
        output.mkdir(mode=0o700)
        for path in (
            "diagnostics",
            "work",
            "work/source",
            "work/home",
            "work/tmp",
            "work/config",
            "work/cache",
        ):
            (output / path).mkdir(mode=0o700)
        with open_root(source) as descriptor:
            copied = scan_tree(descriptor, output / "work/source")
        if copied.files != original.files:
            raise ScanFailure("source_changed", "Selected source changed while being copied")
        (output / "work/source").chmod(0o555)
        (output / "work/rule.yaml").write_bytes(selected_rule)
        (output / "work/rule.yaml").chmod(0o444)
        (output / "tool-preparation.json").write_bytes(marker)
    except ScanFailure:
        raise
    except (ValueError, OSError, CaptureFailure, AnalysisFailure) as exc:
        raise ScanFailure(
            "invalid_scan_input", "Source/tool is unreadable or unapproved, or output is not new"
        ) from exc
    records: list[ScanCommand] = []
    reasons: tuple[Reason, ...] = ()
    snapshot = None
    raw_artifact = ingestion_artifact = provenance_artifact = scanner = None
    interrupted = False
    raw_path = output / "diagnostics/raw.sarif"
    try:
        env = scanner_environment(output, environment)
        executable = str(environment / "bin/semgrep")
        version = command(
            [executable, "--version", "--disable-version-check"],
            stage="version",
            root=output,
            env=env,
            records=records,
            timeout=30,
        )
        if version.decode("utf-8").strip() != VERSION:
            raise ScanFailure(
                "scanner_version", "Prepared Semgrep version does not match the pinned profile"
            )
        command(
            [executable, *scan_arguments(output)],
            stage="scan",
            root=output,
            env=env,
            records=records,
            timeout=120,
            sarif=raw_path,
        )
        raw = read_local(output, "diagnostics/raw.sarif", MAX_SARIF_BYTES)
        document = validate_import(raw)
        with open_root(source) as descriptor:
            after_original = scan_tree(descriptor)
        with open_root(output / "work/source") as descriptor:
            after_copy = scan_tree(descriptor)
        if (
            after_original.files != original.files
            or after_copy.files != original.files
            or after_copy.excluded_paths
            or (output / "work/rule.yaml").read_bytes() != selected_rule
            or rule_bytes() != selected_rule
            or profile_bytes() != profile_data
            or read_local(environment, "prepared.json", MAX_DOCUMENT_BYTES) != marker
        ):
            raise ScanFailure(
                "source_or_policy_changed",
                "Source copy, original, rule, or tool metadata changed during scanning",
            )
        publish(output / "ingestion.json", document.model_dump_json(indent=2) + "\n")
        captured = capture_source(output / "ingestion.json", source, output / "capture")
        if (
            captured.files != original.files
            or captured.snapshot.fingerprint != fixture.fingerprint
            or any(b.location != "present" for b in captured.bindings)
        ):
            raise ScanFailure(
                "capture_mismatch", "Published capture does not match the bytes scanned"
            )
        verify_capture(output / "capture/snapshot")
        raw_artifact = artifact(raw_path, output, "scan:sarif")
        ingestion_artifact = artifact(output / "ingestion.json", output, "scan:ingestion")
        provenance_artifact = artifact(
            output / "capture/snapshot/provenance.json", output, "scan:provenance"
        )
        snapshot = captured.snapshot
        scanner = document.runs[0].scanner
    except KeyboardInterrupt:
        interrupted = True
        reasons = (
            Reason(
                code="scan_interrupted", message="Scan interrupted; scanner process group stopped"
            ),
        )
    except (ValueError, OSError, CaptureFailure) as exc:
        code = exc.code if isinstance(exc, ScanFailure) else "scan_failed"
        reasons = (
            Reason(
                code=code,
                message="Controlled scan did not establish a complete source association; see logs",
            ),
        )
    finally:
        if raw_path.is_file() and raw_artifact is None:
            truncated = raw_path.stat().st_size > MAX_SARIF_BYTES
            if truncated:
                with raw_path.open("r+b") as stream:
                    stream.truncate(MAX_SARIF_BYTES)
            raw_artifact = artifact(raw_path, output, "scan:sarif", truncated=truncated)
        receipt = ScanReceipt(
            schema_version="1.0",
            profile="fixture-semgrep-v1",
            id="scan:" + uuid4().hex,
            fixture_id=fixture.id,
            source_fingerprint=fixture.fingerprint,
            scanned_files=original.files,
            profile_sha256=hashlib.sha256(profile_data).hexdigest(),
            rule_id=policy().rule_id,
            rule_sha256=hashlib.sha256(selected_rule).hexdigest(),
            tool_preparation=artifact(output / "tool-preparation.json", output, "scan:tool"),
            scanner=scanner,
            outcome="completed" if snapshot is not None else "failed",
            snapshot=snapshot,
            raw_sarif=raw_artifact,
            ingestion=ingestion_artifact,
            provenance=provenance_artifact,
            commands=tuple(records),
            reasons=reasons,
        )
        publish(output / "scan.json", receipt.model_dump_json(indent=2) + "\n")
    if interrupted:
        raise KeyboardInterrupt
    return receipt
