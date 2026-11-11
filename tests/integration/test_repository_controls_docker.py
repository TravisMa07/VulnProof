"""Real restricted controls with synthetic static evidence; no vulnerability probes."""

import json
import os
from pathlib import Path
from typing import Any

import pytest
from tests.repository_control_support import control_inputs

from vulnproof.runner.controls import check_repository
from vulnproof.runner.docker import DockerClient
from vulnproof.runner.repository import prepare_repository_image, sha

pytestmark = pytest.mark.skipif(
    not os.environ.get("VULNPROOF_CONTROL_DOCKER_SOCKET"),
    reason="opt-in repository control Docker tests",
)


def prepared_args(root: Path, module: str, mode: str) -> dict[str, Any]:
    args = control_inputs(root, module, mode)
    wheels = Path(os.environ["VULNPROOF_CONTROL_WHEELHOUSE"]).absolute()
    declared = [
        {"filename": path.name, "sha256": sha(path.read_bytes())}
        for path in sorted(wheels.glob("*.whl"))
    ]
    assert declared, "Provide the prepared, pinned Flask wheelhouse"
    if mode == "missing_dependency":
        declared = [w for w in declared if w["filename"].startswith("blinker-")]
    config = root / "image.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "entry_point": module + ":service",
                "platform": os.environ.get("VULNPROOF_CONTROL_PLATFORM", "linux/amd64"),
                "wheels": declared,
            }
        )
    )
    args["socket"] = Path(os.environ["VULNPROOF_CONTROL_DOCKER_SOCKET"])
    output = root / "real-prepared"
    prepare_repository_image(args["scan"], config, wheels, args["socket"], output)
    args["preparation"] = output / "prepared-image.json"
    return args


@pytest.mark.parametrize(
    ("module", "mode", "reason"),
    [
        ("exports/web.py", "normal", "control_matched"),
        ("unfamiliar/server.py", "noise", "control_matched"),
        ("exports/web.py", "wrong_body", "body_mismatch"),
        ("exports/web.py", "redirect", "status_mismatch"),
        ("exports/web.py", "large", "response_limit"),
        ("exports/web.py", "import_failed", "application_import_failed"),
        ("exports/web.py", "missing_dependency", "dependency_missing"),
        ("exports/web.py", "startup_timeout", "startup_timeout"),
        ("exports/web.py", "factory", "unsupported_application"),
        ("exports/web.py", "debug", "debug_enabled"),
        ("exports/web.py", "missing_symbol", "application_symbol_missing"),
        ("exports/web.py", "request_timeout", "request_failed"),
    ],
)
def test_real_controls(tmp_path: Path, module: str, mode: str, reason: str) -> None:
    args = prepared_args(tmp_path, module, mode)
    report = check_repository(**args)
    assert report.driver is not None, report.model_dump_json(indent=2)
    assert report.driver.reason == reason, report.model_dump_json(indent=2)
    assert report.succeeded == (reason == "control_matched")
    assert report.cleanup == "verified_absent"
    assert report.policy_verified and all(report.driver.checks.values())
    if mode == "redirect":
        assert report.driver.status == 302
    if mode == "noise":
        logs = "".join(p.read_text() for p in (args["output"] / "diagnostics").glob("*.log"))
        assert "application stdout is separate" in logs


@pytest.mark.parametrize("failure", ["deadline", "flood", "interrupted"])
def test_real_failure_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    args = prepared_args(
        tmp_path, "exports/web.py", "flood" if failure == "flood" else "startup_timeout"
    )
    original = DockerClient.run

    def operation(self: DockerClient, arguments: list[str], stage: str, **kwargs: Any) -> bytes:
        if stage == "start" and failure == "deadline":
            kwargs["timeout"] = 0.1
        if stage == "start" and failure == "interrupted":
            raise KeyboardInterrupt
        return original(self, arguments, stage, **kwargs)

    monkeypatch.setattr(DockerClient, "run", operation)
    if failure == "interrupted":
        with pytest.raises(KeyboardInterrupt):
            check_repository(**args)
        report = json.loads((args["output"] / "attempt.json").read_bytes())
        assert report["execution"] == "interrupted" and report["cleanup"] == "verified_absent"
    else:
        result = check_repository(**args)
        assert result.execution == ("timed_out" if failure == "deadline" else "output_limit")
        assert result.cleanup == "verified_absent"


def test_real_cli_sigterm_cleanup(tmp_path: Path) -> None:
    import shutil
    import signal
    import subprocess
    import sys
    import time

    args = prepared_args(tmp_path, "exports/web.py", "startup_timeout")
    argv = ["check-repository", "--authorize-execution"]
    names = {"socket": "docker-socket", "preparation": "prepared-image"}
    for name, value in args.items():
        if name != "authorize_execution":
            argv.extend(["--" + names.get(name, name.replace("_", "-")), str(value)])
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys; from vulnproof.cli import main; sys.exit(main())",
            *argv,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 10
        reservation = args["output"] / "reservation.json"
        docker = shutil.which("docker")
        assert docker
        while time.monotonic() < deadline:
            if process.poll() is not None:
                pytest.fail("CLI stopped before the interruption test")
            if reservation.exists():
                name = json.loads(reservation.read_bytes())["container_name"]
                observed = subprocess.run(
                    [
                        docker,
                        "--host",
                        "unix://" + str(args["socket"]),
                        "inspect",
                        "--format={{.State.Running}}",
                        name,
                    ],
                    capture_output=True,
                    timeout=3,
                )
                if observed.returncode == 0 and observed.stdout.strip() == b"true":
                    break
            time.sleep(0.05)
        else:
            pytest.fail("Container did not start before interruption deadline")
        process.send_signal(signal.SIGTERM)
        output, _ = process.communicate(timeout=30)
        assert process.returncode == 130, output.decode()
        report = json.loads((args["output"] / "attempt.json").read_bytes())
        assert report["execution"] == "interrupted" and report["cleanup"] == "verified_absent"
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=30)
