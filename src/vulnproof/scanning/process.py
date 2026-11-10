"""Supervise a trusted scanner; bound retained files and stop its process group."""

import subprocess
import time
from pathlib import Path

from vulnproof.static.process import artifact, stop_group

from .models import MAX_LOG_BYTES, MAX_SARIF_BYTES, ScanCommand


class ScanFailure(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def command(
    args: list[str],
    *,
    stage: str,
    root: Path,
    env: dict[str, str],
    records: list[ScanCommand],
    timeout: float,
    sarif: Path | None = None,
    coverage: Path | None = None,
) -> bytes:
    reports = [p for p in (sarif, coverage) if p is not None]
    stdout = root / "diagnostics" / f"{stage}.stdout"
    stderr = root / "diagnostics" / f"{stage}.stderr"
    process: subprocess.Popen[bytes] | None = None
    outcome = "start_failed"
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = subprocess.Popen(
                args,
                cwd=root / "work/source",
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                start_new_session=True,
            )
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    outcome = "timed_out"
                    raise ScanFailure(
                        "scanner_timeout", "Pinned Semgrep operation exceeded its deadline"
                    )
                if stdout.stat().st_size + stderr.stat().st_size > MAX_LOG_BYTES or (
                    any(p.exists() and p.stat().st_size > MAX_SARIF_BYTES for p in reports)
                ):
                    outcome = "output_limit"
                    raise ScanFailure(
                        "scanner_output_limit", "Pinned Semgrep exceeded its output bound"
                    )
                time.sleep(0.02)
            if stdout.stat().st_size + stderr.stat().st_size > MAX_LOG_BYTES or (
                any(p.exists() and p.stat().st_size > MAX_SARIF_BYTES for p in reports)
            ):
                outcome = "output_limit"
                raise ScanFailure(
                    "scanner_output_limit", "Pinned Semgrep exceeded its output bound"
                )
            if process.returncode != 0:
                outcome = "failed"
                raise ScanFailure(
                    "scanner_failed", "Pinned Semgrep exited unsuccessfully; see retained logs"
                )
            outcome = "completed"
            return stdout.read_bytes()
    except KeyboardInterrupt:
        outcome = "interrupted"
        raise
    except OSError as exc:
        raise ScanFailure(
            "scanner_start_failed", "Unable to execute or log the prepared Semgrep tool"
        ) from exc
    finally:
        if process is not None:
            stop_group(process)
        remaining = MAX_LOG_BYTES
        artifacts = []
        for path in (stdout, stderr):
            if not path.exists():
                path.touch(exist_ok=False)
            size = path.stat().st_size
            truncated = size > remaining
            if truncated:
                with path.open("r+b") as stream:
                    stream.truncate(remaining)
            remaining -= min(size, remaining)
            artifacts.append(
                artifact(path, root, f"log:{stage}:{path.suffix[1:]}", truncated=truncated)
            )
        records.append(
            ScanCommand.model_validate(
                {
                    "stage": stage,
                    "outcome": outcome,
                    "return_code": process.returncode if process else None,
                    "stdout": artifacts[0],
                    "stderr": artifacts[1],
                }
            )
        )
