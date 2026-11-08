"""Descriptor-relative reads; do not follow source symlinks or execute source code."""

import hashlib
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from vulnproof.models.common import relative_path

from .models import (
    EXCLUDED_NAMES,
    MAX_DEPTH,
    MAX_ENTRIES,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    CapturedFile,
)


class CaptureFailure(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def excluded(path: str) -> bool:
    return any(part in EXCLUDED_NAMES for part in path.split("/"))


@contextmanager
def open_root(root: Path) -> Iterator[int]:
    """Reject symlinks in the selected root and its ancestors, too."""
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in root.absolute().parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
        yield descriptor
    finally:
        os.close(descriptor)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


@dataclass(frozen=True)
class Tree:
    files: tuple[CapturedFile, ...]
    excluded_paths: tuple[str, ...]
    directories: tuple[str, ...]
    identities: tuple[tuple[str, tuple[int, ...]], ...]
    # Raw Git object identity computed locally; no clean filters or object reads.
    git_objects: tuple[tuple[str, str, str, bool], ...]


def scan_tree(root_fd: int, destination: Path | None = None) -> Tree:
    files: list[CapturedFile] = []
    exclusions: list[str] = []
    directories: list[str] = []
    identities: list[tuple[str, tuple[int, ...]]] = []
    git_objects: list[tuple[str, str, str, bool]] = []
    entry_count, total = 0, 0

    def walk(directory_fd: int, prefix: str, depth: int) -> None:
        nonlocal entry_count, total
        if depth > MAX_DEPTH:
            raise CaptureFailure("source_limit", "Source exceeds the directory-depth limit")
        entries: list[str] = []
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                entry_count += 1
                if entry_count > MAX_ENTRIES:
                    raise CaptureFailure("source_limit", "Source exceeds the entry-count limit")
                entries.append(entry.name)
        for name in sorted(entries):
            path = f"{prefix}/{name}" if prefix else name
            try:
                path.encode("utf-8")
                relative_path(path)
                if any(ord(c) < 32 or ord(c) == 127 for c in path):
                    raise ValueError("control character")
            except (ValueError, UnicodeError) as exc:
                raise CaptureFailure(
                    "invalid_source_path", "Source contains an unsupported path"
                ) from exc
            if excluded(path):
                exclusions.append(path)
                continue
            initial = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(initial.st_mode):
                raise CaptureFailure("source_symlink", "Included source symlinks are not supported")
            is_directory = stat.S_ISDIR(initial.st_mode)
            if not is_directory and not stat.S_ISREG(initial.st_mode):
                raise CaptureFailure(
                    "special_source_file", "Included source must be regular files or directories"
                )
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if is_directory:
                flags |= os.O_DIRECTORY
            descriptor = os.open(name, flags, dir_fd=directory_fd)
            try:
                if _identity(initial) != _identity(os.fstat(descriptor)):
                    raise CaptureFailure("source_changed", "Source changed while being opened")
                identities.append((path, _identity(initial)))
                if is_directory:
                    directories.append(path)
                    if destination is not None:
                        (destination / path).mkdir()
                    walk(descriptor, path, depth + 1)
                else:
                    if len(files) >= MAX_FILES or initial.st_size > MAX_FILE_BYTES:
                        raise CaptureFailure(
                            "source_limit", "Source exceeds a file-count or file-size limit"
                        )
                    with os.fdopen(os.dup(descriptor), "rb") as stream:
                        data = stream.read(MAX_FILE_BYTES + 1)
                    total += len(data)
                    if len(data) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                        raise CaptureFailure("source_limit", "Source exceeds a byte limit")
                    executable = bool(initial.st_mode & 0o111)
                    files.append(
                        CapturedFile(
                            path=path,
                            sha256=hashlib.sha256(data).hexdigest(),
                            size_bytes=len(data),
                            executable=executable,
                            line_count=data.count(b"\n")
                            + data.count(b"\r")
                            - data.count(b"\r\n")
                            + int(bool(data) and not data.endswith((b"\n", b"\r"))),
                        )
                    )
                    blob = f"blob {len(data)}\0".encode() + data
                    git_objects.append(
                        (
                            path,
                            hashlib.sha1(blob, usedforsecurity=False).hexdigest(),
                            hashlib.sha256(blob).hexdigest(),
                            executable,
                        )
                    )
                    if destination is not None:
                        with (destination / path).open("xb") as stream:
                            stream.write(data)
                            stream.flush()
                            os.fsync(stream.fileno())
                        (destination / path).chmod(0o555 if executable else 0o444)
                if _identity(initial) != _identity(os.fstat(descriptor)):
                    raise CaptureFailure("source_changed", "Source changed while being read")
                if _identity(initial) != _identity(
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                ):
                    raise CaptureFailure("source_changed", "Source entry changed while being read")
            finally:
                os.close(descriptor)

    walk(root_fd, "", 0)
    return Tree(
        tuple(sorted(files, key=lambda f: f.path)),
        tuple(sorted(exclusions)),
        tuple(sorted(directories)),
        tuple(sorted(identities)),
        tuple(sorted(git_objects)),
    )
