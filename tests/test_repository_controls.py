import json
from pathlib import Path
from typing import Any

import pytest
from tests.repository_control_support import control_inputs
from tests.runner_support import fake_docker

from vulnproof.cli import main
from vulnproof.runner.control_driver import CHECKS
from vulnproof.runner.controls import RepositoryControlAttempt, check_repository
from vulnproof.runner.docker import DockerClient, RunnerFailure
from vulnproof.runner.repository import COMMAND, sha


def driver() -> dict[str, Any]:
    return dict(
        schema_version="1.0",
        profile="repository-control-v1",
        checks=dict.fromkeys(CHECKS, True),
        application_started=True,
        control="passed",
        reason="control_matched",
        status=200,
        body_sha256=sha(b"manual\n"),
        body_bytes=7,
        truncated=False,
    )


def setup(
    root: Path, monkeypatch: pytest.MonkeyPatch, **faults: Any
) -> tuple[dict[str, Any], Path]:
    args = control_inputs(root)
    fake = fake_docker(
        root,
        monkeypatch,
        repository=True,
        prepared_command=COMMAND,
        repository_driver=faults.pop("repository_driver", driver()),
        **faults,
    )
    return args, fake


def calls(fake: Path) -> list[str]:
    path = fake / "calls.jsonl"
    return (
        [json.loads(line)["args"][0] for line in path.read_text().splitlines()]
        if path.exists()
        else []
    )


def test_control_preserves_evidence_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args, fake = setup(tmp_path, monkeypatch)
    report = check_repository(**args)
    assert report.succeeded
    assert report.scanner_source_state == "unverified"
    assert report.authorization_scope == "repository_control_only"
    assert report.request["request_target"] == "/export?document=manual.txt"
    assert report.supporting_path_ids and set(report.supporting_path_ids) <= set(report.path_ids)
    assert report.cleanup == "verified_absent"
    assert (
        RepositoryControlAttempt.model_validate_json((args["output"] / "attempt.json").read_bytes())
        == report
    )
    assert (args["output"] / "reservation.json").exists()
    assert "build" not in calls(fake) and "pull" not in calls(fake)


@pytest.mark.parametrize(
    "edit",
    [
        "authorize",
        "plan",
        "discovery",
        "config",
        "source",
        "finding",
        "old",
        "driver",
        "image_source",
        "entry",
        "blocked",
    ],
)
def test_admission_rejects_before_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, edit: str
) -> None:
    args, fake = setup(tmp_path, monkeypatch)
    if edit == "authorize":
        args["authorize_execution"] = False
    elif edit == "finding":
        args["finding_id"] = "missing"
    elif edit == "source":
        (args["scan"] / "snapshot/exports/web.py").chmod(0o644)
        (args["scan"] / "snapshot/exports/web.py").write_text("changed")
    elif edit in ("plan", "discovery", "config"):
        args[edit].write_text("{}")
    elif edit == "blocked":
        config = json.loads(args["config"].read_bytes())
        config["endpoints"][0].pop("control_sha256")
        args["config"].write_text(json.dumps(config))
        from vulnproof.planning.repository import plan_repository

        args["plan"].write_text(
            plan_repository(
                args["scan"],
                args["investigation"],
                args["correlation"],
                args["discovery"],
                args["config"],
            )
        )
    else:
        data = json.loads(args["preparation"].read_bytes())
        if edit == "old":
            data["schema_version"] = "1.0"
        elif edit == "driver":
            data["driver_sha256"] = "b" * 64
        elif edit == "entry":
            data["configuration"]["entry_point"] = "exports/web.py:other"
        else:
            data["source_fingerprint"] = "b" * 64
        args["preparation"].write_text(json.dumps(data))
    with pytest.raises(RunnerFailure):
        check_repository(**args)
    assert not calls(fake) and not args["output"].exists()


@pytest.mark.parametrize(
    "fault",
    [
        {"host_changes": {"NetworkMode": "host"}},
        {"partial_create": True},
        {"malformed": "container-inspect"},
        {"image_bad": True},
    ],
)
def test_rejected_runtime_never_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: dict[str, Any]
) -> None:
    args, fake = setup(tmp_path, monkeypatch, **fault)
    report = check_repository(**args)
    assert not report.succeeded and "start" not in calls(fake)
    assert report.cleanup == ("not_needed" if fault.get("image_bad") else "verified_absent")


@pytest.mark.parametrize(
    "fault",
    [{"exit": 1}, {"oom": True}, {"flood": True}, {"cleanup_failed": True}, {"malformed": "start"}],
)
def test_failed_attempt_not_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: dict[str, Any]
) -> None:
    args, fake = setup(tmp_path, monkeypatch, **fault)
    report = check_repository(**args)
    assert not report.succeeded and "rm" in calls(fake)
    assert report.cleanup == ("unverified" if fault.get("cleanup_failed") else "verified_absent")


def test_control_failure_separate_from_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed = driver() | {"control": "failed", "reason": "status_mismatch", "status": 404}
    args, _ = setup(tmp_path, monkeypatch, repository_driver=observed)
    report = check_repository(**args)
    assert report.execution == "completed" and not report.succeeded
    assert report.driver and report.driver.status == 404


def test_false_hash_success_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args, _ = setup(tmp_path, monkeypatch, repository_driver=driver() | {"body_sha256": "b" * 64})
    report = check_repository(**args)
    assert not report.succeeded and report.driver is None


def test_timeout_cleans_container(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args, _ = setup(tmp_path, monkeypatch, driver_sleep=True)
    original = DockerClient.run

    def shortened(self: DockerClient, arguments: list[str], stage: str, **kwargs: Any) -> bytes:
        if stage == "start":
            kwargs["timeout"] = 0.1
        return original(self, arguments, stage, **kwargs)

    monkeypatch.setattr(DockerClient, "run", shortened)
    report = check_repository(**args)
    assert report.execution == "timed_out" and report.cleanup == "verified_absent"


def test_interruption_publishes_after_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args, _ = setup(tmp_path, monkeypatch)
    original = DockerClient.run

    def interrupted(self: DockerClient, arguments: list[str], stage: str, **kwargs: Any) -> bytes:
        if stage == "start":
            raise KeyboardInterrupt
        return original(self, arguments, stage, **kwargs)

    monkeypatch.setattr(DockerClient, "run", interrupted)
    with pytest.raises(KeyboardInterrupt):
        check_repository(**args)
    report = RepositoryControlAttempt.model_validate_json(
        (args["output"] / "attempt.json").read_bytes()
    )
    assert report.execution == "interrupted" and report.cleanup == "verified_absent"


def test_cli_control(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args, _ = setup(tmp_path, monkeypatch)
    argv = ["check-repository", "--authorize-execution"]
    names = {"socket": "docker-socket", "preparation": "prepared-image"}
    for name, value in args.items():
        if name != "authorize_execution":
            argv.extend(["--" + names.get(name, name.replace("_", "-")), str(value)])
    assert main(argv) == 0
