"""Installed recipe approvals and fixed create/inspection policy."""

import hashlib
import json
from importlib.resources import files
from typing import Any

from vulnproof.static.analysis import fixture_manifest

from .docker import RunnerFailure
from .models import Recipe, RunnerApproval

DRIVER_COMMAND = ["python", "/fixture/runner_driver.py"]
TMPFS = "/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777"
DAEMON_FORMAT = '--format={"os":{{json .OSType}},"memory":{{json .MemoryLimit}},"swap":{{json .SwapLimit}},"pids":{{json .PidsLimit}},"cpu":{{json .CPUCfsQuota}},"security":{{json .SecurityOptions}}}'


def verify_daemon(value: object) -> None:
    if not isinstance(value, dict):
        raise RunnerFailure(
            "unsupported_daemon", "Docker daemon capability response must be an object"
        )
    if (
        value.get("os") != "linux"
        or any(value.get(key) is not True for key in ("memory", "swap", "pids", "cpu"))
        or not isinstance(value.get("security"), list)
        or any(not isinstance(s, str) or s.startswith("name=rootless") for s in value["security"])
    ):
        raise RunnerFailure(
            "unsupported_daemon",
            "A local rootful Linux-container daemon with CPU, memory/swap, and PID limit support is required",
        )


def approval_bytes() -> bytes:
    return files("vulnproof.runner").joinpath("approvals.json").read_bytes()


def runner_approval() -> RunnerApproval:
    approval = RunnerApproval.model_validate_json(approval_bytes())
    known = {f.id for f in fixture_manifest().fixtures}
    if len({r.fixture_id for r in approval.recipes}) != len(approval.recipes):
        raise ValueError("duplicate recipe approval")
    if {r.fixture_id for r in approval.recipes} != known:
        raise ValueError("runner approval must cover the reviewed fixture identities")
    required = {
        "Dockerfile",
        "runner_driver.py",
        "app.py",
        "requirements.lock",
        "downloads/example.txt",
    }
    if any(r.fixture_id not in known or set(r.inputs) != required for r in approval.recipes):
        raise ValueError("recipe must reference approved fixtures and exact build inputs")
    return approval


def recipe_hash(recipe: Recipe) -> str:
    return hashlib.sha256(
        json.dumps(recipe.inputs, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def create_args(name: str, image: str) -> list[str]:
    return [
        "create",
        "--name",
        name,
        "--pull=never",
        "--network=none",
        "--read-only",
        "--label=vulnproof.attempt=" + name,
        "--ipc=private",
        "--cgroupns=private",
        "--user=10001:10001",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--cpus=1",
        "--memory=256m",
        "--memory-swap=256m",
        "--pids-limit=64",
        "--log-driver=none",
        "--tmpfs=" + TMPFS,
        "--no-healthcheck",
        "--restart=no",
        "--entrypoint=python",
        "--workdir=/fixture",
        image,
        "/fixture/runner_driver.py",
    ]


def verify_image(value: dict[str, Any], image: str) -> None:
    config = value["Config"]
    if (
        value["Id"] != image
        or value["Os"] != "linux"
        or config["User"] != "10001:10001"
        or config["WorkingDir"] != "/fixture"
        or config.get("Entrypoint")
        or config["Cmd"] != DRIVER_COMMAND
        or config.get("Volumes")
        or config.get("OnBuild")
        or config.get("Healthcheck")
    ):
        raise RunnerFailure("image_policy_mismatch", "Prepared image configuration is incompatible")


def verify_container(value: dict[str, Any], image: str, name: str) -> None:
    host, config = value["HostConfig"], value["Config"]
    checks = [
        value["Image"] == image,
        config["User"] == "10001:10001",
        config.get("Labels", {}).get("vulnproof.attempt") == name,
        config["Entrypoint"] == ["python"],
        config["Cmd"] == ["/fixture/runner_driver.py"],
        config["WorkingDir"] == "/fixture",
        not config.get("Volumes"),
        config.get("Healthcheck", {}).get("Test") == ["NONE"],
        host["ReadonlyRootfs"] is True,
        host["NetworkMode"] == "none",
        not host.get("PortBindings"),
        not host.get("PublishAllPorts"),
        host["Privileged"] is False,
        host.get("CapDrop") == ["ALL"],
        not host.get("CapAdd"),
        host.get("SecurityOpt") in (["no-new-privileges"], ["no-new-privileges:true"]),
        host["NanoCpus"] == 1_000_000_000,
        host["Memory"] == 268435456,
        host["MemorySwap"] == 268435456,
        host["PidsLimit"] == 64,
        host.get("Tmpfs") == {"/tmp": TMPFS.split(":", 1)[1]},
        host["LogConfig"]["Type"] == "none",
        host["RestartPolicy"]["Name"] == "no",
        not host.get("Binds"),
        not host.get("Mounts"),
        all(m["Type"] == "tmpfs" for m in value.get("Mounts", [])),
        not host.get("Devices"),
        not host.get("DeviceRequests"),
        not host.get("DeviceCgroupRules"),
        not host.get("PidMode"),
        host.get("IpcMode") == "private",
        host.get("CgroupnsMode") == "private",
        host.get("UsernsMode") != "host",
        not host.get("UTSMode"),
        not host.get("Links"),
        not host.get("VolumesFrom"),
        not value["State"]["Running"],
        value["State"]["Status"] == "created",
    ]
    if not all(checks):
        raise RunnerFailure(
            "container_policy_mismatch",
            "Created container failed required policy checks; not started",
        )
