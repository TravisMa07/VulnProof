import os
from pathlib import Path
from typing import Any

import pytest
from tests.onboarding_support import inputs

from vulnproof.onboarding.preparation import prepare_application
from vulnproof.onboarding.runtime import exercise_application

pytestmark = pytest.mark.skipif(
    not os.environ.get("VULNPROOF_CONTROL_DOCKER_SOCKET"),
    reason="Opt-in application onboarding Docker checks",
)


@pytest.mark.parametrize("mode", ["http", "harness", "failed_initialize", "flood"])
def test_application_lifecycle(tmp_path: Path, mode: str) -> None:
    args = inputs(tmp_path, mode)
    socket = Path(os.environ["VULNPROOF_CONTROL_DOCKER_SOCKET"])
    prepared = tmp_path / "prepared"
    prepare_application(
        **args,
        wheelhouse=tmp_path / "wheels",
        socket=socket,
        output=prepared,
        authorize_preparation=True,
    )
    result = exercise_application(
        **args,
        preparation=prepared / "prepared-application.json",
        socket=socket,
        output=tmp_path / "attempt",
        authorize_execution=True,
    )
    assert result.policy_verified and all(result.cleanup.values()), result.model_dump_json(indent=2)
    assert result.outcome == ("completed" if mode in ("http", "harness") else "failed"), (
        result.model_dump_json(indent=2)
    )
    assert result.vulnerability_assessment is None
    if mode == "http":
        assert result.observation and result.observation["egress_probe_connected"] is False
        assert all(result.observation["runtime_checks"].values())
        assert len(result.observation["callbacks"]) == 1
        assert all(c["matched"] for c in result.observation["controls"])
        again = exercise_application(
            **args,
            preparation=prepared / "prepared-application.json",
            socket=socket,
            output=tmp_path / "again",
            authorize_execution=True,
        )
        assert again.outcome == "completed" and all(again.cleanup.values())


@pytest.mark.parametrize(
    "failure", ["network_policy", "container_policy", "timeout", "interrupted", "observer_tamper"]
)
def test_rejection_and_interruption_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    import json

    from vulnproof.runner.docker import DockerClient, RunnerFailure

    args = inputs(tmp_path)
    socket = Path(os.environ["VULNPROOF_CONTROL_DOCKER_SOCKET"])
    prepared = tmp_path / "prepared"
    prepare_application(
        **args,
        wheelhouse=tmp_path / "wheels",
        socket=socket,
        output=prepared,
        authorize_preparation=True,
    )
    original = DockerClient.run

    def changed(self: DockerClient, argv: list[str], stage: str, **kwargs: Any) -> bytes:
        if stage == "start" and failure in ("timeout", "interrupted"):
            if failure == "interrupted":
                raise KeyboardInterrupt
            raise RunnerFailure("command_timeout", "Synthetic timeout at attach")
        data = original(self, argv, stage, **kwargs)
        if stage == "start" and failure == "observer_tamper":
            value = json.loads(data)
            value["controls"][0]["body_sha256"] = "0" * 64
            return json.dumps(value).encode()
        if stage == "network-inspect" and failure == "network_policy":
            value = json.loads(data)
            value[0]["Internal"] = False
            return json.dumps(value).encode()
        if stage == "inspect" and failure == "container_policy":
            value = json.loads(data)
            value[0]["HostConfig"]["Memory"] = 0
            return json.dumps(value).encode()
        return data

    monkeypatch.setattr(DockerClient, "run", changed)
    call = dict(
        **args,
        preparation=prepared / "prepared-application.json",
        socket=socket,
        output=tmp_path / "attempt",
        authorize_execution=True,
    )
    if failure == "interrupted":
        with pytest.raises(KeyboardInterrupt):
            exercise_application(**call)
        document = json.loads((tmp_path / "attempt/result.json").read_bytes())
        assert document["outcome"] == "interrupted" and all(document["cleanup"].values())
    else:
        result = exercise_application(**call)
        assert result.outcome == "failed" and all(result.cleanup.values())
        if failure.endswith("policy"):
            assert result.policy_verified is False
            assert not any(c.stage.startswith("start") for c in result.commands)


def test_cli_sigterm_cleans_owned_resources(tmp_path: Path) -> None:
    import json
    import shutil
    import subprocess
    import sys
    import time

    from vulnproof.onboarding.planning import inspect_application

    args = inputs(tmp_path)
    settings = json.loads(args["config"].read_bytes())
    settings["command"] = ["python", "-c", "import time; time.sleep(30)"]
    settings["readiness"] = {"timeout_seconds": 20}
    args["config"].write_text(json.dumps(settings))
    args["plan"].write_text(inspect_application(args["scan"], args["config"]).model_dump_json())
    socket = Path(os.environ["VULNPROOF_CONTROL_DOCKER_SOCKET"])
    prepared = tmp_path / "prepared"
    prepare_application(
        **args,
        wheelhouse=tmp_path / "wheels",
        socket=socket,
        output=prepared,
        authorize_preparation=True,
    )
    argv = [
        sys.executable,
        "-c",
        "from vulnproof.cli import main; raise SystemExit(main())",
        "exercise-application",
    ]
    for name, value in dict(
        **args,
        preparation=prepared / "prepared-application.json",
        docker_socket=socket,
        output=tmp_path / "attempt",
    ).items():
        argv += ["--" + name.replace("_", "-"), str(value)]
    argv += ["--authorize-execution"]
    process = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            reservation = tmp_path / "attempt/reservation.json"
            if reservation.exists():
                names = json.loads(reservation.read_bytes())["containers"]
                check = subprocess.run(
                    [
                        str(shutil.which("docker")),
                        "--host",
                        "unix://" + str(socket),
                        "inspect",
                        "--format={{.State.Running}}",
                        names[-1],
                    ],
                    capture_output=True,
                    text=True,
                )
                if check.returncode == 0 and check.stdout.strip() == "true":
                    break
            time.sleep(0.1)
        else:
            raise AssertionError("Observer did not reach attach stage")
        process.terminate()
        assert process.wait(timeout=30) == 130
        result = json.loads((tmp_path / "attempt/result.json").read_bytes())
        assert result["outcome"] == "interrupted" and all(result["cleanup"].values())
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
