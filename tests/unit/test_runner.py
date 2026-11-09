"""Runner admission, restricted command construction, and lifecycle failure tests."""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from tests.runner_support import fake_docker, runner_inputs
from tests.static_pipeline import ROOT, codeql_sarif

from vulnproof.cli import main
from vulnproof.runner import RunnerAttempt, RunnerFailure, run_diagnostics
from vulnproof.runner.docker import OUTPUT_BYTES, DockerClient
from vulnproof.runner.preparation import build_sources, prepare_images
from vulnproof.runner.profile import runner_approval


def calls(root: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]


def test_success_records_policy_driver_state_and_verified_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = runner_inputs(tmp_path)
    tool = fake_docker(tmp_path, monkeypatch)
    report = run_diagnostics(**args)
    assert report.execution == "completed"
    assert report.cleanup == "verified_absent"
    assert report.policy_verified
    assert report.driver is not None and all(report.driver.checks.values())
    assert report.container_exit_code == 0 and report.oom_killed is False
    assert report.authorization_scope == "fixture_diagnostics_only"
    assert report.scanner_source_state == "unverified"
    assert (
        RunnerAttempt.model_validate_json((args["output"] / "attempt.json").read_bytes()) == report
    )
    assert (args["output"] / "reservation.json").exists()
    operations = [c["args"][0] for c in calls(tool)]
    assert operations.index("create") < operations.index("start") < operations.index("rm")
    assert not {"build", "pull", "run", "exec"}.intersection(operations)
    assert sum(c.log.size_bytes or 0 for c in report.commands) <= OUTPUT_BYTES


def test_authorization_required_before_docker_or_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = runner_inputs(tmp_path)
    tool = fake_docker(tmp_path, monkeypatch)
    args["authorize_execution"] = False
    with pytest.raises(RunnerFailure, match="authorization"):
        run_diagnostics(**args)
    assert not (tool / "calls.jsonl").exists()
    assert not args["output"].exists()


@pytest.mark.parametrize("edit", ["plan", "finding", "source", "image_tag", "recipe", "approval"])
def test_invalid_admission_never_calls_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, edit: str
) -> None:
    args = runner_inputs(tmp_path)
    tool = fake_docker(tmp_path, monkeypatch)
    if edit == "finding":
        args["finding_id"] = "missing"
    elif edit == "plan":
        path = args["plan"]
        data = json.loads(path.read_bytes())
        data["catalog_sha256"] = "b" * 64
        path.write_text(json.dumps(data))
    else:
        path = args["preparation"]
        data = json.loads(path.read_bytes())
        if edit == "approval":
            data["approval_sha256"] = "b" * 64
        elif edit == "recipe":
            data["images"][0]["recipe_sha256"] = "b" * 64
        elif edit == "source":
            data["images"][0]["source_fingerprint"] = "b" * 64
        else:
            data["images"][0]["image_id"] = "unapproved:latest"
        path.write_text(json.dumps(data))
    with pytest.raises(RunnerFailure):
        run_diagnostics(**args)
    assert not (tool / "calls.jsonl").exists()


@pytest.mark.parametrize(
    "change",
    [
        {"Privileged": True},
        {"NetworkMode": "host"},
        {"ReadonlyRootfs": False},
        {"Memory": 0},
        {"MemorySwap": -1},
        {"PidsLimit": 0},
        {"NanoCpus": 0},
        {"CapAdd": ["SYS_ADMIN"]},
        {"Binds": ["/:/host"]},
        {"Devices": [{"PathOnHost": "/dev/sda"}]},
        {"PortBindings": {"80/tcp": [{"HostPort": "8080"}]}},
        {"IpcMode": "host"},
        {"PidMode": "host"},
        {"CgroupnsMode": "host"},
        {"UsernsMode": "host"},
        {"SecurityOpt": ["seccomp=unconfined"]},
        {"Tmpfs": {}},
    ],
)
def test_policy_mismatch_is_never_started_and_is_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: dict[str, Any]
) -> None:
    args = runner_inputs(tmp_path)
    tool = fake_docker(tmp_path, monkeypatch, host_changes=change)
    report = run_diagnostics(**args)
    assert not report.policy_verified
    assert report.execution == "not_started"
    assert report.cleanup == "verified_absent"
    assert "start" not in [c["args"][0] for c in calls(tool)]


@pytest.mark.parametrize(
    "control",
    [{"image_bad": True}, {"os": "windows"}, {"fail": "info"}, {"malformed": "image-inspect"}],
)
def test_precreation_failure_never_creates_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, control: dict[str, Any]
) -> None:
    args = runner_inputs(tmp_path)
    tool = fake_docker(tmp_path, monkeypatch, **control)
    report = run_diagnostics(**args)
    assert report.cleanup == "not_needed"
    assert "create" not in [c["args"][0] for c in calls(tool)]


@pytest.mark.parametrize(
    "control",
    [
        {"partial_create": True},
        {"driver_bad": True},
        {"exit": 42},
        {"oom": True},
        {"malformed": "state"},
    ],
)
def test_failures_after_create_are_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, control: dict[str, Any]
) -> None:
    args = runner_inputs(tmp_path)
    fake_docker(tmp_path, monkeypatch, **control)
    report = run_diagnostics(**args)
    assert report.execution != "completed"
    assert report.cleanup == "verified_absent"


def test_output_limit_retains_prefix_and_reserves_cleanup_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = runner_inputs(tmp_path)
    fake_docker(tmp_path, monkeypatch, flood=True)
    report = run_diagnostics(**args)
    assert report.execution == "output_limit"
    assert report.cleanup == "verified_absent"
    assert any(c.log.truncated for c in report.commands)
    assert sum(c.log.size_bytes or 0 for c in report.commands) <= OUTPUT_BYTES


def test_timeout_stops_cli_and_removes_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = runner_inputs(tmp_path)
    fake_docker(tmp_path, monkeypatch, driver_sleep=True)
    original = DockerClient.run

    def shorter(self: DockerClient, command: list[str], stage: str, **kwargs: Any) -> bytes:
        if stage == "start":
            kwargs["timeout"] = 0.2
        return original(self, command, stage, **kwargs)

    monkeypatch.setattr(DockerClient, "run", shorter)
    report = run_diagnostics(**args)
    assert report.execution == "timed_out"
    assert report.cleanup == "verified_absent"


@pytest.mark.parametrize("control", [{"cleanup_failed": True}, {"cleanup_unavailable": True}])
def test_cleanup_unknown_is_separate_from_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, control: dict[str, Any]
) -> None:
    args = runner_inputs(tmp_path)
    fake_docker(tmp_path, monkeypatch, **control)
    report = run_diagnostics(**args)
    assert report.execution == "completed"
    assert report.cleanup == "unverified"
    assert "cleanup_unverified" in {r.code for r in report.reasons}


def test_foreign_container_is_never_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = runner_inputs(tmp_path)
    tool = fake_docker(tmp_path, monkeypatch, foreign_owner=True)
    report = run_diagnostics(**args)
    assert report.cleanup == "unverified"
    assert "rm" not in [c["args"][0] for c in calls(tool)]


def test_environment_and_endpoint_are_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = runner_inputs(tmp_path)
    tool = fake_docker(tmp_path, monkeypatch)
    for key in (
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_API_VERSION",
        "HTTP_PROXY",
        "PYTHONPATH",
    ):
        monkeypatch.setenv(key, "untrusted-marker")
    run_diagnostics(**args)
    for call in calls(tool):
        assert call["prefix"][:2] == ["--host", "unix://" + str(args["socket"])]
        assert "untrusted-marker" not in call["env"].values()


def cli_args(args: dict[str, Any]) -> list[str]:
    result = ["check-runner", "--authorize-execution"]
    for name in ("capture", "analysis", "correlation", "plan", "finding_id", "output"):
        result.extend(["--" + name.replace("_", "-"), str(args[name])])
    result.extend(
        ["--prepared-images", str(args["preparation"]), "--docker-socket", str(args["socket"])]
    )
    return result


def test_cli_success_then_no_overwrite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = runner_inputs(tmp_path)
    fake_docker(tmp_path, monkeypatch)
    assert main(cli_args(args)) == 0
    before = (args["output"] / "attempt.json").read_bytes()
    assert main(cli_args(args)) == 2
    assert (args["output"] / "attempt.json").read_bytes() == before


def test_cli_sigterm_runs_cleanup_and_retains_interruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = runner_inputs(tmp_path)
    tool = fake_docker(tmp_path, monkeypatch, driver_sleep=True)
    env = dict(os.environ, PATH=str(tool) + os.pathsep + os.defpath)
    process = subprocess.Popen(
        [sys.executable, "-m", "vulnproof", *cli_args(args)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            state = tool / "state.json"
            if state.exists() and json.loads(state.read_bytes()).get("started"):
                break
            time.sleep(0.02)
        else:
            raise AssertionError("Fake driver did not start")
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=10)
        assert process.returncode == 130
        report = RunnerAttempt.model_validate_json((args["output"] / "attempt.json").read_bytes())
        assert report.execution == "interrupted" and report.cleanup == "verified_absent"
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


def test_creation_timeout_after_acceptance_still_cleans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = runner_inputs(tmp_path)
    fake_docker(tmp_path, monkeypatch, partial_create_sleep=True)
    original = DockerClient.run

    def shorter(self: DockerClient, command: list[str], stage: str, **kwargs: Any) -> bytes:
        if stage == "create":
            kwargs["timeout"] = 0.2
        return original(self, command, stage, **kwargs)

    monkeypatch.setattr(DockerClient, "run", shorter)
    report = run_diagnostics(**args)
    assert report.execution == "timed_out" and report.cleanup == "verified_absent"
    assert not report.policy_verified


def test_blocked_entry_cannot_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = runner_inputs(tmp_path, raw=codeql_sarif(results=0))
    tool = fake_docker(tmp_path, monkeypatch)
    with pytest.raises(RunnerFailure, match="draft"):
        run_diagnostics(**args)
    assert not (tool / "calls.jsonl").exists()


@pytest.mark.parametrize(
    "endpoint", ["relative.sock", "tcp://remote.invalid:2375", "/tmp/../socket", "/tmp/bad\nname"]
)
def test_nonlocal_or_ambiguous_endpoint_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, endpoint: str
) -> None:
    args = runner_inputs(tmp_path)
    tool = fake_docker(tmp_path, monkeypatch)
    args["socket"] = Path(endpoint)
    report = run_diagnostics(**args)
    assert report.execution == "not_started" and report.cleanup == "not_needed"
    assert report.reasons[0].code == "invalid_endpoint"
    assert not (tool / "calls.jsonl").exists()


def test_missing_docker_is_actionable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = runner_inputs(tmp_path)
    monkeypatch.setattr("shutil.which", lambda name: None)
    report = run_diagnostics(**args)
    assert report.reasons[0].code == "docker_missing"
    assert report.cleanup == "not_needed"


def test_stderr_does_not_corrupt_driver_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = runner_inputs(tmp_path)
    fake_docker(tmp_path, monkeypatch, stderr_warning=True)
    report = run_diagnostics(**args)
    assert report.execution == "completed"
    start = next(c for c in report.commands if c.stage == "start")
    assert b"Synthetic warning" in (args["output"] / start.log.path).read_bytes()


def test_preparation_builds_only_fixed_contexts_and_does_not_execute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = fake_docker(tmp_path, monkeypatch)
    record = prepare_images(ROOT, tmp_path / "fake.sock", tmp_path / "prepared")
    assert len(record.images) == 2
    operations = [c["args"][0] for c in calls(tool)]
    assert operations.count("build") == 2
    assert not {"create", "start", "run", "exec"}.intersection(operations)
    for recipe in runner_approval().recipes:
        context = tmp_path / "prepared/work" / recipe.fixture_id
        assert {
            p.relative_to(context).as_posix() for p in context.rglob("*") if p.is_file()
        } == set(recipe.inputs)


def test_modified_preparation_inputs_are_rejected_before_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = fake_docker(tmp_path, monkeypatch)
    repository = tmp_path / "repository"
    for variant in ("vulnerable", "patched"):
        for source in build_sources(variant).values():
            path = repository / source
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / source).read_bytes())
    (repository / "fixtures/runner/driver.py").write_text("unapproved")
    with pytest.raises(RunnerFailure, match="Build inputs changed"):
        prepare_images(repository, tmp_path / "fake.sock", tmp_path / "prepared")
    assert not (tool / "calls.jsonl").exists()


@pytest.mark.parametrize("source", ["plan", "preparation"])
def test_symlinked_evidence_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    args = runner_inputs(tmp_path)
    tool = fake_docker(tmp_path, monkeypatch)
    link = tmp_path / "linked.json"
    link.symlink_to(args[source])
    args[source] = link
    with pytest.raises(RunnerFailure):
        run_diagnostics(**args)
    assert not (tool / "calls.jsonl").exists()


def test_output_cannot_be_inside_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = runner_inputs(tmp_path)
    fake_docker(tmp_path, monkeypatch)
    args["output"] = args["capture"] / "inside"
    with pytest.raises(RunnerFailure, match="outside"):
        run_diagnostics(**args)
    assert not args["output"].exists()


@pytest.mark.parametrize(
    "change",
    [
        {"memory": False},
        {"swap": False},
        {"pids": False},
        {"cpu": False},
        {"security": ["name=rootless"]},
        {"memory": "true"},
    ],
)
def test_missing_daemon_enforcement_support_rejected_before_create(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: dict[str, Any],
) -> None:
    args = runner_inputs(tmp_path)
    tool = fake_docker(tmp_path, monkeypatch, daemon_changes=change)
    report = run_diagnostics(**args)
    assert report.reasons[0].code == "unsupported_daemon"
    assert "create" not in [c["args"][0] for c in calls(tool)]
