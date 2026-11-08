"""Bounded subprocess logs, deadlines and process-group cleanup on POSIX hosts."""

import hashlib
import os
import selectors
import signal
import subprocess
import time
from pathlib import Path

from vulnproof.models import Artifact

from .models import MAX_LOG_BYTES, MAX_SARIF_BYTES, CommandRecord


class AnalysisFailure(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def artifact(path: Path, root: Path, identifier: str, *, truncated: bool = False) -> Artifact:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return Artifact(
        id=identifier,
        path=path.relative_to(root).as_posix(),
        media_type="application/sarif+json" if path.suffix == ".sarif" else "text/plain",
        sha256=digest,
        size_bytes=path.stat().st_size,
        truncated=truncated,
    )


def stop_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def run_command(
    command: list[str],
    *,
    stage: str,
    root: Path,
    env: dict[str, str],
    timeout: float,
    records: list[CommandRecord],
    sarif: Path | None = None,
) -> bytes:
    log = root / "diagnostics" / f"{stage}.log"
    start = time.monotonic()
    process: subprocess.Popen[bytes] | None = None
    outcome = "start_failed"
    output = bytearray()
    log_truncated = False
    try:
        with log.open("xb") as target:
            process = subprocess.Popen(
                command,
                cwd=root / "work",
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            assert process.stdout is not None
            deadline = start + timeout
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        outcome = "timed_out"
                        raise AnalysisFailure(
                            "command_timeout", "CodeQL command exceeded its deadline"
                        )
                    if (
                        sarif is not None
                        and sarif.exists()
                        and sarif.stat().st_size > MAX_SARIF_BYTES
                    ):
                        outcome = "output_limit"
                        raise AnalysisFailure(
                            "sarif_limit", "CodeQL SARIF exceeded the retained-output limit"
                        )
                    for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                        chunk = os.read(key.fd, 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        available = MAX_LOG_BYTES - len(output)
                        output.extend(chunk[:available])
                        target.write(chunk[:available])
                        target.flush()
                        if len(chunk) > available:
                            log_truncated = True
                            outcome = "output_limit"
                            raise AnalysisFailure("log_limit", "CodeQL command log was truncated")
            try:
                return_code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                outcome = "timed_out"
                raise AnalysisFailure(
                    "command_timeout", "CodeQL command exceeded its deadline"
                ) from exc
            if return_code != 0:
                outcome = "nonzero_exit"
                raise AnalysisFailure(
                    "command_failed", "CodeQL command exited unsuccessfully; see its log"
                )
            outcome = "completed"
            return bytes(output)
    except KeyboardInterrupt:
        outcome = "interrupted"
        raise
    except OSError as exc:
        raise AnalysisFailure(
            "command_start_failed", "Unable to start or log the CodeQL command"
        ) from exc
    finally:
        if process is not None:
            stop_group(process)
            if process.stdout is not None:
                process.stdout.close()
        if log.is_file():
            records.append(
                CommandRecord.model_validate(
                    {
                        "stage": stage,
                        "outcome": outcome,
                        "return_code": None if process is None else process.returncode,
                        "duration_seconds": max(0.0, time.monotonic() - start),
                        "log": artifact(log, root, "log:" + stage, truncated=log_truncated),
                    }
                )
            )
