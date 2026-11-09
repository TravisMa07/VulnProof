"""Recheck scan/capture relationships before deriving matched finding records."""

import hashlib
from pathlib import Path

from vulnproof.artifacts import read_local
from vulnproof.correlation import policy
from vulnproof.ingest import IngestionDocument
from vulnproof.models import Artifact, Finding, Reason, SourceBinding
from vulnproof.provenance import CaptureFailure, verify_capture
from vulnproof.provenance.filesystem import open_root, scan_tree
from vulnproof.static import AnalysisFailure
from vulnproof.static.analysis import admit_fixture
from vulnproof.static.process import artifact

from .engine import profile_bytes, rule_bytes, scan_profile, validate_import
from .models import (
    MAX_DOCUMENT_BYTES,
    MAX_LOG_BYTES,
    MAX_SARIF_BYTES,
    AssociatedFinding,
    ScanReceipt,
    ToolPreparation,
    VerifiedScan,
)
from .process import ScanFailure


def _checked(root: Path, reference: Artifact, limit: int) -> bytes:
    data = read_local(root, reference.path, limit)
    if (
        reference.truncated is not False
        or reference.sha256 != hashlib.sha256(data).hexdigest()
        or reference.size_bytes != len(data)
    ):
        raise ScanFailure(
            "scan_artifact_changed", "Retained scan artifact is changed or incomplete"
        )
    return data


def verify_scan(root: Path) -> VerifiedScan:
    try:
        return _verify(root.absolute())
    except ScanFailure:
        raise
    except (ValueError, OSError, CaptureFailure, AnalysisFailure) as exc:
        raise ScanFailure(
            "invalid_scan_evidence",
            "Controlled-scan evidence is unreadable, changed, or inconsistent",
        ) from exc


def _verify(root: Path) -> VerifiedScan:
    receipt_bytes = read_local(root, "scan.json", MAX_DOCUMENT_BYTES)
    receipt = ScanReceipt.model_validate_json(receipt_bytes)
    if (
        receipt.outcome != "completed"
        or receipt.raw_sarif is None
        or receipt.ingestion is None
        or receipt.provenance is None
    ):
        raise ScanFailure(
            "scan_not_completed",
            "Only completed controlled scans can establish a source association",
        )
    if (
        receipt.profile_sha256 != hashlib.sha256(profile_bytes()).hexdigest()
        or receipt.rule_id != policy().rule_id
        or receipt.rule_sha256 != policy().rule_sha256
    ):
        raise ScanFailure(
            "scan_policy_changed", "Scan profile or rule does not match installed policy"
        )
    fixture = admit_fixture(receipt.source_fingerprint)
    if fixture.id != receipt.fixture_id:
        raise ValueError("fixture mismatch")
    # Require producer layout, not arbitrary artifact aliases into the evidence directory.
    if (
        receipt.raw_sarif.path != "diagnostics/raw.sarif"
        or receipt.ingestion.path != "ingestion.json"
        or receipt.tool_preparation.path != "tool-preparation.json"
        or receipt.provenance.path != "capture/snapshot/provenance.json"
    ):
        raise ValueError("unexpected scan artifact layout")
    marker = ToolPreparation.model_validate_json(
        _checked(root, receipt.tool_preparation, MAX_DOCUMENT_BYTES)
    )
    if marker.lock_sha256 != scan_profile().lock_sha256:
        raise ValueError("tool preparation mismatch")
    for record in receipt.commands:
        if (
            record.stdout.path != f"diagnostics/{record.stage}.stdout"
            or record.stderr.path != f"diagnostics/{record.stage}.stderr"
        ):
            raise ValueError("unexpected command artifact layout")
        out = _checked(root, record.stdout, MAX_LOG_BYTES)
        err = _checked(root, record.stderr, MAX_LOG_BYTES)
        if len(out) + len(err) > MAX_LOG_BYTES:
            raise ValueError("command output limit")
    raw = _checked(root, receipt.raw_sarif, MAX_SARIF_BYTES)
    ingestion_bytes = _checked(root, receipt.ingestion, MAX_DOCUMENT_BYTES)
    document = validate_import(raw)
    if ingestion_bytes != read_local(root, "capture/snapshot/ingestion.json", MAX_DOCUMENT_BYTES):
        raise ValueError("capture ingestion mismatch")
    if (
        IngestionDocument.model_validate_json(ingestion_bytes) != document
        or receipt.scanner != document.runs[0].scanner
    ):
        raise ValueError("normalization mismatch")
    _checked(root, receipt.provenance, MAX_DOCUMENT_BYTES)
    provenance = verify_capture(root / "capture/snapshot")
    if (
        provenance.snapshot != receipt.snapshot
        or provenance.files != receipt.scanned_files
        or provenance.sarif_sha256 != hashlib.sha256(raw).hexdigest()
        or any(b.location != "present" for b in provenance.bindings)
    ):
        raise ValueError("capture differs from the scanned scope")
    with open_root(root / "work/source") as descriptor:
        tree = scan_tree(descriptor)
    if (
        tree.files != receipt.scanned_files
        or tree.excluded_paths
        or read_local(root, "work/rule.yaml", MAX_LOG_BYTES) != rule_bytes()
    ):
        raise ValueError("private scan inputs changed")
    associated = []
    for item in document.findings:
        original = item.finding
        bound = Finding(
            id=original.id,
            scanner=original.scanner,
            rule_id=original.rule_id,
            original_ref=original.original_ref,
            cwes=original.cwes,
            location=original.location,
            artifact_ids=original.artifact_ids,
            source=SourceBinding(
                expected_snapshot_id=provenance.snapshot.id,
                observed_snapshot_id=provenance.snapshot.id,
                state="matched",
                reason=Reason(
                    code="controlled_scan_verified",
                    message="Pinned controlled scan report and reviewed rule are bound to these exact captured bytes",
                ),
            ),
        )
        associated.append(AssociatedFinding(original=original, bound=bound))
    if (
        verify_capture(root / "capture/snapshot") != provenance
        or read_local(root, "scan.json", MAX_DOCUMENT_BYTES) != receipt_bytes
    ):
        raise ValueError("evidence changed during verification")
    proof = (
        artifact(root / "scan.json", root, "scan:receipt"),
        receipt.raw_sarif,
        receipt.ingestion,
        receipt.tool_preparation,
        receipt.provenance,
        artifact(root / "work/rule.yaml", root, "scan:rule"),
        *(a for c in receipt.commands for a in (c.stdout, c.stderr)),
    )
    return VerifiedScan(
        schema_version="1.0",
        receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        ingestion_sha256=hashlib.sha256(ingestion_bytes).hexdigest(),
        sarif_sha256=hashlib.sha256(raw).hexdigest(),
        snapshot=provenance.snapshot,
        proof_artifacts=proof,
        findings=tuple(associated),
    )
