"""Captured content identity is distinct from the scanner's unknown source identity."""

import hashlib
import json
from typing import Literal, Self

from pydantic import model_validator

from vulnproof.models import Reason, SourceBinding, SourceFile, SourceSnapshot
from vulnproof.models.common import (
    CommitId,
    Contract,
    Identifier,
    NonNegative,
    RelativePath,
    Sha256,
)

EXCLUDED_NAMES = (
    ".git",
    ".venv",
    ".cache",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
)
MAX_FILES = 1024
MAX_ENTRIES = 4096
MAX_DEPTH = 32
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


class CapturedFile(Contract):
    path: RelativePath
    sha256: Sha256
    size_bytes: NonNegative
    executable: bool
    line_count: NonNegative


def fingerprint(files: tuple[CapturedFile, ...]) -> str:
    """Exact UTF-8 canonical manifest, with an algorithm-specific domain prefix."""
    rows = [[f.path, f.sha256, f.size_bytes, f.executable] for f in files]
    data = json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b"vulnproof-source-v1\n" + data).hexdigest()


class CapturePolicy(Contract):
    excluded_names: tuple[str, ...] = EXCLUDED_NAMES
    max_files: int = MAX_FILES
    max_entries: int = MAX_ENTRIES
    max_depth: int = MAX_DEPTH
    max_file_bytes: int = MAX_FILE_BYTES
    max_total_bytes: int = MAX_TOTAL_BYTES


class GitObservation(Contract):
    state: Literal["observed", "unknown"]
    commit_id: CommitId | None = None
    source_prefix: str | None = None
    # This compares captured scope to HEAD, not the index or whole repository.
    comparison: Literal["captured_scope_against_head"] = "captured_scope_against_head"
    reason: Reason | None = None


class FindingSource(Contract):
    finding_id: Identifier
    original_expected_snapshot_id: Identifier
    source: SourceBinding
    location: Literal["present", "missing", "line_out_of_range"]
    reasons: tuple[Reason, ...] = ()


class ProvenanceDocument(Contract):
    schema_version: Literal["1.0"]
    fingerprint_algorithm: Literal["vulnproof-source-v1"]
    ingestion_sha256: Sha256
    sarif_sha256: Sha256
    snapshot: SourceSnapshot
    files: tuple[CapturedFile, ...]
    git: GitObservation
    policy: CapturePolicy
    excluded_paths: tuple[RelativePath, ...]
    bindings: tuple[FindingSource, ...]
    diagnostics: tuple[Reason, ...] = ()

    @model_validator(mode="after")
    def consistent_capture(self) -> Self:
        paths = [f.path for f in self.files]
        if paths != sorted(set(paths)):
            raise ValueError("captured files must be unique and sorted by relative path")
        if self.policy != CapturePolicy():
            raise ValueError("unsupported capture policy")
        if self.snapshot.fingerprint != fingerprint(self.files):
            raise ValueError("snapshot fingerprint disagrees with manifest")
        if self.snapshot.files != tuple(
            SourceFile(path=f.path, sha256=f.sha256) for f in self.files
        ):
            raise ValueError("snapshot file hashes disagree with manifest")
        if self.snapshot.commit_id != self.git.commit_id:
            raise ValueError("snapshot commit and Git observation disagree")
        if self.git.state == "unknown":
            if self.git.commit_id is not None or self.snapshot.dirty is not None:
                raise ValueError("unknown Git metadata cannot claim commit or dirty state")
        elif self.git.commit_id is None or self.snapshot.dirty is None:
            raise ValueError("observed Git metadata requires commit and dirty state")
        ids = [b.finding_id for b in self.bindings]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate finding binding")
        for binding in self.bindings:
            if (
                binding.source.expected_snapshot_id != self.snapshot.id
                or binding.source.state != "unverified"
                or binding.source.observed_snapshot_id is not None
            ):
                raise ValueError("scanner association must remain explicitly unverified")
        return self
