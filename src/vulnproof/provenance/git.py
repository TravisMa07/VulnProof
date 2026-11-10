"""Optional read-only Git observations; never run status, filters, hooks, or fetch."""

import os
import re
import selectors
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from vulnproof.models import Reason

from .filesystem import CaptureFailure, Tree, excluded
from .models import GitObservation

COMMIT_PATTERN = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
_MAX_OUTPUT = 1024 * 1024


@dataclass(frozen=True)
class GitState:
    observation: GitObservation
    # Relative path, object ID, and executable bit for HEAD's captured scope.
    entries: tuple[tuple[str, str, bool], ...] = ()


def _command(root: Path, args: list[str]) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        raise ValueError("Git unavailable")
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    command = [
        executable,
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=" + os.devnull,
        "-C",
        str(root),
        *args,
    ]
    with subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
    ) as process:
        assert process.stdout is not None
        output = bytearray()
        deadline = time.monotonic() + 5
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise ValueError("Git observation timed out")
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > _MAX_OUTPUT:
                        raise ValueError("Git output limit")
            if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                raise ValueError("Git observation unavailable")
            return bytes(output)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def checkout_head(root: Path) -> str | None:
    """Observe only HEAD for intake, including checkouts too large for tree capture."""
    try:
        commit = _command(root, ["rev-parse", "--verify", "HEAD"]).decode().strip()
    except (ValueError, OSError):
        return None
    return commit if re.fullmatch(COMMIT_PATTERN, commit) else None


def observe_git(root: Path) -> GitState:
    try:
        commit = _command(root, ["rev-parse", "--verify", "HEAD"]).decode().strip()
        if re.fullmatch(COMMIT_PATTERN, commit) is None:
            raise ValueError("unknown HEAD")
        top = Path(os.fsdecode(_command(root, ["rev-parse", "--show-toplevel"]).rstrip(b"\n")))
        prefix = root.relative_to(top).as_posix()
        if prefix == ".":
            prefix = ""
        raw = _command(root, ["ls-tree", "--full-name", "-r", "-z", commit, "--", "."])
        entries: list[tuple[str, str, bool]] = []
        for item in raw.split(b"\0"):
            if not item:
                continue
            header, name = item.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split()
            path = name.decode("utf-8")
            if prefix:
                if not path.startswith(prefix + "/"):
                    raise ValueError("unexpected Git path scope")
                path = path[len(prefix) + 1 :]
            if excluded(path):
                continue
            if kind != "blob" or mode not in {"100644", "100755"}:
                raise ValueError("unsupported Git tree entry")
            if re.fullmatch(COMMIT_PATTERN, oid) is None:
                raise ValueError("invalid Git object ID")
            entries.append((path, oid, mode == "100755"))
        return GitState(
            GitObservation(state="observed", commit_id=commit, source_prefix=prefix),
            tuple(sorted(entries)),
        )
    except ValueError, OSError, subprocess.SubprocessError:
        return GitState(
            GitObservation(
                state="unknown",
                reason=Reason(
                    code="git_unknown",
                    message="Git metadata is absent, unavailable, or unsupported",
                ),
            )
        )


def dirty_against_head(state: GitState, tree: Tree) -> bool | None:
    if state.observation.state == "unknown":
        return None
    assert state.observation.commit_id is not None
    sha256_repo = len(state.observation.commit_id) == 64
    observed = tuple(
        (path, sha256 if sha256_repo else sha1, executable)
        for path, sha1, sha256, executable in tree.git_objects
    )
    return state.entries != observed


def check_revision(expected: str | None, state: GitState, dirty: bool | None) -> None:
    if expected is None:
        return
    if re.fullmatch(COMMIT_PATTERN, expected) is None:
        raise CaptureFailure("invalid_revision", "Expected a full lowercase commit ID")
    if state.observation.commit_id is None:
        raise CaptureFailure(
            "revision_unknown", "Cannot verify a required revision without Git metadata"
        )
    if state.observation.commit_id != expected or dirty is not False:
        raise CaptureFailure(
            "revision_mismatch", "Captured scope does not match the required clean revision"
        )
