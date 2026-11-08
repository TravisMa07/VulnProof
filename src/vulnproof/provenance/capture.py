"""Capture a bounded source tree; preserve the original ingestion document."""

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from vulnproof.ingest import IngestionDocument, ingest_sarif
from vulnproof.models import Reason, SourceBinding, SourceFile, SourceSnapshot

from .filesystem import CaptureFailure, Tree, open_root, scan_tree
from .git import COMMIT_PATTERN, check_revision, dirty_against_head, observe_git
from .models import CapturePolicy, FindingSource, ProvenanceDocument, fingerprint

MAX_DOCUMENT_BYTES = 64 * 1024 * 1024


def _read_regular(path: Path, limit: int) -> bytes:
    import stat

    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise CaptureFailure("invalid_document", "Expected a regular, non-symlink document")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise CaptureFailure("document_limit", "Document exceeds its byte limit")
    return data


def _load_ingestion(data: bytes) -> IngestionDocument:
    try:
        document = IngestionDocument.model_validate_json(data)
        # Do not accept findings that disagree with their retained original SARIF.
        if ingest_sarif(document.raw_sarif.encode("utf-8")) != document:
            raise ValueError("normalized report was changed")
        return document
    except ValueError as exc:
        raise CaptureFailure(
            "invalid_ingestion", "Ingestion document is invalid or not reproducible"
        ) from exc


def _reported_revisions(document: IngestionDocument) -> tuple[tuple[str, ...], bool]:
    raw = json.loads(document.raw_sarif)
    revisions: set[str] = set()
    unknown = False
    for run in document.runs:
        if not run.supported:
            continue
        claims = raw["runs"][run.run_index].get("versionControlProvenance", [])
        if not isinstance(claims, list):
            raise CaptureFailure("invalid_revision", "Invalid reported revision metadata")
        # Multiple repositories cannot be mapped to one selected root implicitly.
        if len(claims) > 1:
            raise CaptureFailure(
                "ambiguous_revision", "Multiple reported repositories require an explicit mapping"
            )
        for claim in claims:
            if not isinstance(claim, dict):
                raise CaptureFailure("invalid_revision", "Invalid reported revision metadata")
            revision = claim.get("revisionId")
            if isinstance(revision, str) and re.fullmatch(COMMIT_PATTERN, revision):
                revisions.add(revision)
            else:
                unknown = True
    return tuple(sorted(revisions)), unknown


def _bindings(
    document: IngestionDocument, snapshot: SourceSnapshot, tree: Tree
) -> tuple[FindingSource, ...]:
    files = {f.path: f for f in tree.files}
    bindings: list[FindingSource] = []
    for item in document.findings:
        finding = item.finding
        file = files.get(finding.location.path)
        location = "present"
        reasons: tuple[Reason, ...] = ()
        if file is None:
            location = "missing"
            reasons = (
                Reason(
                    code="finding_file_missing",
                    message="Finding file is absent from captured scope",
                ),
            )
        elif (finding.location.end_line or finding.location.start_line) > file.line_count:
            location = "line_out_of_range"
            reasons = (
                Reason(
                    code="finding_line_out_of_range",
                    message="Finding line exceeds captured file length",
                ),
            )
        bindings.append(
            FindingSource.model_validate(
                {
                    "finding_id": finding.id,
                    "original_expected_snapshot_id": finding.source.expected_snapshot_id,
                    "source": SourceBinding(
                        expected_snapshot_id=snapshot.id,
                        reason=Reason(
                            code="scanner_source_unverified",
                            message="Captured target is known; the scanner's input bytes are not verified",
                        ),
                    ),
                    "location": location,
                    "reasons": reasons,
                }
            )
        )
    return tuple(bindings)


def _remove_owned_output(path: Path) -> None:
    # Only called for the new directory successfully reserved by this invocation.
    for directory, _, _ in os.walk(path):
        Path(directory).chmod(0o700)
    shutil.rmtree(path)


def capture_source(
    ingestion: Path, root: Path, output: Path, *, expected_commit: str | None = None
) -> ProvenanceDocument:
    """Reserve a new output directory and publish output/snapshot only when complete."""
    root = Path(os.path.abspath(root))
    output = Path(os.path.abspath(output))
    if output.resolve().is_relative_to(root.resolve()):
        raise CaptureFailure(
            "output_inside_source", "Output must be outside the selected source root"
        )
    ingestion_bytes = _read_regular(ingestion, MAX_DOCUMENT_BYTES)
    document = _load_ingestion(ingestion_bytes)
    # Source root is validated before output reservation, so bad roots publish nothing.
    with open_root(root) as root_fd:
        initial_root = os.fstat(root_fd)
        before_git = observe_git(root)
        output.mkdir(mode=0o700)
        try:
            pending = Path(tempfile.mkdtemp(prefix=".pending-", dir=output))
            source = pending / "source"
            source.mkdir()
            first = scan_tree(root_fd, source)
            second = scan_tree(root_fd)
            if first != second:
                raise CaptureFailure("source_changed", "Source changed during capture")
            with open_root(root) as current_fd:
                current = os.fstat(current_fd)
                if (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_ctime_ns) != (
                    initial_root.st_dev,
                    initial_root.st_ino,
                    initial_root.st_mtime_ns,
                    initial_root.st_ctime_ns,
                ):
                    raise CaptureFailure(
                        "source_changed", "Selected root was replaced during capture"
                    )
            after_git = observe_git(root)
            if before_git != after_git:
                raise CaptureFailure("source_changed", "Git identity changed during capture")
            dirty = dirty_against_head(before_git, first)
            check_revision(expected_commit, before_git, dirty)
            revisions, unknown_revision = _reported_revisions(document)
            if len(revisions) > 1:
                raise CaptureFailure(
                    "revision_mismatch", "Runs declare different revisions for one selected root"
                )
            for revision in revisions:
                if before_git.observation.commit_id is not None:
                    check_revision(revision, before_git, dirty)
            digest = fingerprint(first.files)
            snapshot = SourceSnapshot(
                id="snapshot:" + digest,
                fingerprint=digest,
                commit_id=before_git.observation.commit_id,
                dirty=dirty,
                files=tuple(SourceFile(path=f.path, sha256=f.sha256) for f in first.files),
            )
            diagnostics: tuple[Reason, ...] = (
                () if before_git.observation.reason is None else (before_git.observation.reason,)
            )
            if document.status == "partial":
                diagnostics += (
                    Reason(
                        code="ingestion_partial",
                        message="Input ingestion was partial; its diagnostics are preserved",
                    ),
                )
            if revisions and before_git.observation.commit_id is None:
                diagnostics += (
                    Reason(
                        code="reported_revision_unverified",
                        message="Reported revision could not be checked without Git metadata",
                    ),
                )
            if unknown_revision:
                diagnostics += (
                    Reason(
                        code="reported_revision_unknown",
                        message="A reported revision is absent or not a full commit ID",
                    ),
                )
            provenance = ProvenanceDocument(
                schema_version="1.0",
                fingerprint_algorithm="vulnproof-source-v1",
                ingestion_sha256=hashlib.sha256(ingestion_bytes).hexdigest(),
                sarif_sha256=document.input_sha256,
                snapshot=snapshot,
                files=first.files,
                git=before_git.observation,
                policy=CapturePolicy(),
                excluded_paths=first.excluded_paths,
                bindings=_bindings(document, snapshot, first),
                diagnostics=diagnostics,
            )
            (pending / "ingestion.json").write_bytes(ingestion_bytes)
            (pending / "provenance.json").write_text(
                provenance.model_dump_json(indent=2) + "\n", encoding="utf-8"
            )
            # Check the copy itself, not just the original tree, before publication.
            with open_root(source) as copy_fd:
                copied = scan_tree(copy_fd)
            if copied.files != first.files or copied.directories != first.directories:
                raise CaptureFailure("copy_mismatch", "Captured copy differs from the manifest")
            for directory, _, files in os.walk(pending, topdown=False):
                for name in files:
                    path = Path(directory) / name
                    path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
                Path(directory).chmod(0o555)
            # The destination name is inside our exclusively reserved private directory.
            pending.rename(output / "snapshot")
            return provenance
        except BaseException:
            _remove_owned_output(output)
            raise


def verify_capture(path: Path) -> ProvenanceDocument:
    """Rehash stored bytes before a future consumer uses this captured source."""
    try:
        with open_root(Path(os.path.abspath(path))):
            pass
        document = ProvenanceDocument.model_validate_json(
            _read_regular(path / "provenance.json", MAX_DOCUMENT_BYTES)
        )
        ingestion = _read_regular(path / "ingestion.json", MAX_DOCUMENT_BYTES)
        original = _load_ingestion(ingestion)
        if (
            hashlib.sha256(ingestion).hexdigest() != document.ingestion_sha256
            or original.input_sha256 != document.sarif_sha256
        ):
            raise ValueError("ingestion identity mismatch")
        with open_root(path / "source") as descriptor:
            actual = scan_tree(descriptor)
        if actual.files != document.files or actual.excluded_paths:
            raise ValueError("captured bytes differ from manifest")
        if _bindings(original, document.snapshot, actual) != document.bindings:
            raise ValueError("finding association mismatch")
        return document
    except (ValueError, OSError) as exc:
        raise CaptureFailure(
            "invalid_capture", "Capture is unreadable, modified, or inconsistent"
        ) from exc
