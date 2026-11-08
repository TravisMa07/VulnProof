"""Bounded local evidence reads shared by correlation and planning."""

import os
import stat
from pathlib import Path

from vulnproof.models.common import relative_path
from vulnproof.provenance.filesystem import open_root


def read_local(root: Path, path: str, limit: int) -> bytes:
    """Read a regular file without following root, ancestor, or artifact symlinks."""
    relative_path(path)
    with open_root(root) as root_fd:
        descriptor = os.dup(root_fd)
        try:
            parts = path.split("/")
            for part in parts[:-1]:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
                )
                os.close(descriptor)
                descriptor = child
            child = os.open(
                parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor
            )
            with os.fdopen(child, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("artifact is not a regular file")
                data = stream.read(limit + 1)
            if len(data) > limit:
                raise ValueError("artifact exceeds limit")
            return data
        finally:
            os.close(descriptor)
