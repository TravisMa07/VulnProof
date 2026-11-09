"""Fixed local endpoint and bounded Docker CLI subprocesses; no shell execution."""

import os
import selectors
import shutil
import subprocess
import time
from pathlib import Path

from vulnproof.static.process import artifact, stop_group

from .models import DockerCommand

OUTPUT_BYTES = 1024 * 1024
CLEANUP_RESERVE = 64 * 1024


class RunnerFailure(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class DockerClient:
    def __init__(self, socket: Path, root: Path, *, preparation: bool = False) -> None:
        if (
            not socket.is_absolute()
            or ".." in socket.parts
            or any(ord(c) < 32 or ord(c) == 127 for c in str(socket))
            or ":" in str(socket)
        ):
            raise RunnerFailure("invalid_endpoint", "Select an absolute local Unix socket path")
        executable = shutil.which("docker")
        if executable is None:
            raise RunnerFailure(
                "docker_missing", "Docker CLI missing; install Docker Desktop or Engine"
            )
        self.root = root
        self.commands: list[DockerCommand] = []
        self.remaining = OUTPUT_BYTES - CLEANUP_RESERVE
        self.cleanup_remaining = CLEANUP_RESERVE
        config = root / "work/config"
        config.mkdir(parents=True)
        (root / "work/home").mkdir()
        (root / "work/tmp").mkdir()
        # Preparation may invoke the trusted CLI's bundled build plugin, never user config.
        if preparation:
            import json

            plugins = Path(executable).resolve().parent.parent / "cli-plugins"
            if plugins.is_dir():
                (config / "config.json").write_text(
                    json.dumps({"cliPluginsExtraDirs": [str(plugins)]})
                )
        self.prefix = [
            str(Path(executable).absolute()),
            "--host",
            f"unix://{socket}",
            "--config",
            str(config),
        ]
        self.env = {
            "PATH": str(Path(executable).parent) + os.pathsep + os.defpath,
            "HOME": str(root / "work/home"),
            "TMPDIR": str(root / "work/tmp"),
            "LC_ALL": "C",
        }

    def run(
        self,
        args: list[str],
        stage: str,
        *,
        timeout: float = 15,
        expected: tuple[int, ...] = (0,),
        cleanup: bool = False,
    ) -> bytes:
        sequence = len(self.commands)
        log = self.root / "diagnostics" / f"{sequence:02}-{stage}.log"
        start = time.monotonic()
        deadline = start + timeout
        budget = self.cleanup_remaining if cleanup else self.remaining
        # Management responses are small; the attached driver shares the remaining budget.
        limit = min(budget, budget if stage == "start" else 65536)
        process: subprocess.Popen[bytes] | None = None
        outcome = "start_failed"
        stdout = bytearray()
        retained = 0
        truncated = False
        try:
            if limit <= 0:
                raise RunnerFailure("output_limit", "Attempt output budget exhausted")
            with log.open("xb") as target:
                process = subprocess.Popen(
                    [*self.prefix, *args],
                    cwd=self.root / "work",
                    env=self.env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                assert process.stdout is not None and process.stderr is not None
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, True)
                    selector.register(process.stderr, selectors.EVENT_READ, False)
                    while selector.get_map():
                        if time.monotonic() >= deadline:
                            outcome = "timed_out"
                            raise RunnerFailure(
                                "command_timeout", "Docker operation exceeded its deadline"
                            )
                        for key, _ in selector.select(
                            min(0.2, max(0, deadline - time.monotonic()))
                        ):
                            chunk = os.read(key.fd, 8192)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            available = max(0, limit - retained)
                            prefix = chunk[:available]
                            target.write(prefix)
                            target.flush()
                            retained += len(prefix)
                            if key.data:
                                stdout.extend(prefix)
                            if len(chunk) > available:
                                truncated = True
                                outcome = "output_limit"
                                raise RunnerFailure(
                                    "output_limit", "Attempt command output was truncated"
                                )
                try:
                    returncode = process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired as exc:
                    outcome = "timed_out"
                    raise RunnerFailure(
                        "command_timeout", "Docker operation exceeded its deadline"
                    ) from exc
                if returncode not in expected:
                    outcome = "failed"
                    raise RunnerFailure(
                        "docker_command_failed", "Docker operation failed; see retained diagnostics"
                    )
                outcome = "completed"
                return bytes(stdout)
        except KeyboardInterrupt:
            outcome = "interrupted"
            raise
        except OSError as exc:
            raise RunnerFailure(
                "docker_io_failed", "Unable to start or retain Docker operation"
            ) from exc
        finally:
            if cleanup:
                self.cleanup_remaining -= retained
            else:
                self.remaining -= retained
            if process is not None:
                stop_group(process)
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
            if log.is_file():
                self.commands.append(
                    DockerCommand.model_validate(
                        {
                            "stage": stage,
                            "outcome": outcome,
                            "return_code": process.returncode if process else None,
                            "duration_seconds": max(0.0, time.monotonic() - start),
                            "log": artifact(
                                log, self.root, f"log:{sequence}:{stage}", truncated=truncated
                            ),
                        }
                    )
                )
