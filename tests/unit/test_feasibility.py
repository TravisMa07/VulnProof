"""Test experiment boundaries without importing fixtures or requiring external tools."""

import json
import shutil
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from scripts import feasibility


def test_missing_codeql_is_explicit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(feasibility, "CODEQL", tmp_path / "missing-codeql")
    with pytest.raises(feasibility.ExperimentError, match="prepare_codeql.py"):
        feasibility.static(tmp_path)


def test_missing_docker_is_explicit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(feasibility.ExperimentError, match="Docker CLI missing"):
        feasibility.container(tmp_path)


def test_unavailable_daemon_is_explicit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(command: list[str], log: Path, timeout: float) -> str:
        raise feasibility.ExperimentError("daemon not running")

    monkeypatch.setattr(shutil, "which", lambda _: "/fake/docker")
    monkeypatch.setattr(feasibility, "run_logged", fail)
    with pytest.raises(feasibility.ExperimentError, match="Start Docker"):
        feasibility.container(tmp_path)


def test_termination_uses_interrupt_cleanup_path() -> None:
    with pytest.raises(KeyboardInterrupt):
        feasibility.interrupt(15, None)


def path_result(source_line: int = 1, sink_line: int = 2) -> dict[str, Any]:
    def location(line: int) -> dict[str, Any]:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": "app.py"},
                "region": {"startLine": line},
            }
        }

    return {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "py/path-injection",
                        "locations": [location(sink_line)],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {"location": location(source_line)},
                                            {"location": location(sink_line)},
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        ]
    }


def test_requires_path_at_both_expected_endpoints() -> None:
    source = 'name = request.args.get("name")\nopen(path, "rb")'
    feasibility.require_vulnerable_path(path_result(), source)
    wrong_results: list[dict[str, Any]] = [
        {"runs": []},
        path_result(source_line=9),
        path_result(sink_line=9),
    ]
    for wrong in wrong_results:
        with pytest.raises(feasibility.ExperimentError, match="No py/path-injection path"):
            feasibility.require_vulnerable_path(wrong, source)
    empty = path_result()
    empty["runs"][0]["results"][0]["codeFlows"] = []
    with pytest.raises(feasibility.ExperimentError):
        feasibility.require_vulnerable_path(empty, source)


def test_rejects_other_file_with_same_line_numbers() -> None:
    result = path_result()
    result["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = "other.py"
    with pytest.raises(feasibility.ExperimentError):
        feasibility.require_vulnerable_path(result, 'request.args.get("name")\nopen(path, "rb")')


def test_accepts_library_origin_before_request_read() -> None:
    result = path_result()
    locations = result["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    prefix = deepcopy(locations[0])
    prefix["location"]["physicalLocation"]["region"]["startLine"] = 99
    locations.insert(0, prefix)
    feasibility.require_vulnerable_path(result, 'request.args.get("name")\nopen(path, "rb")')


def test_output_is_bounded_even_for_successful_command(tmp_path: Path) -> None:
    log = tmp_path / "output.log"
    with pytest.raises(feasibility.ExperimentError, match="truncated"):
        feasibility.run_logged([sys.executable, "-c", 'print("x" * 10000)'], log, 5, limit=100)
    assert log.stat().st_size == 100


def test_timeout_stops_process(tmp_path: Path) -> None:
    with pytest.raises(feasibility.ExperimentError, match="Deadline"):
        feasibility.run_logged(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            tmp_path / "timeout.log",
            0.2,
        )


def test_nonzero_exit_is_not_success(tmp_path: Path) -> None:
    with pytest.raises(feasibility.ExperimentError, match="exited 7"):
        feasibility.run_logged(
            [sys.executable, "-c", "raise SystemExit(7)"], tmp_path / "exit.log", 5
        )


def policy() -> dict[str, Any]:
    return {
        "Image": "sha256:" + "a" * 64,
        "Config": {"User": "10001:10001"},
        "Mounts": [],
        "HostConfig": {
            "ReadonlyRootfs": True,
            "NetworkMode": "none",
            "PortBindings": {},
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "NanoCpus": 1_000_000_000,
            "Memory": 268435456,
            "MemorySwap": 268435456,
            "PidsLimit": 64,
            "Binds": None,
            "Mounts": None,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777"},
            "LogConfig": {"Type": "none"},
        },
    }


@pytest.mark.parametrize(
    "key,value",
    [
        ("ReadonlyRootfs", False),
        ("NetworkMode", "host"),
        ("Privileged", True),
        ("CapAdd", ["SYS_ADMIN"]),
        ("SecurityOpt", []),
        ("NanoCpus", 0),
        ("Memory", 0),
        ("PidsLimit", 0),
        ("Binds", ["/:/host"]),
        ("PortBindings", {"5000/tcp": [{"HostPort": "5000"}]}),
        ("Tmpfs", {}),
    ],
)
def test_rejects_weakened_container_policy(key: str, value: Any) -> None:
    inspected = policy()
    feasibility.require_container_policy(inspected, inspected["Image"])
    inspected["HostConfig"][key] = value
    with pytest.raises(feasibility.ExperimentError, match="policy mismatch"):
        feasibility.require_container_policy(inspected, inspected["Image"])


@pytest.mark.parametrize("interrupted", [False, True])
def test_cleanup_after_fixture_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupted: bool,
) -> None:
    calls: list[list[str]] = []
    (tmp_path / "diagnostics").mkdir()

    def fake(command: list[str], log: Path, timeout: float, **kwargs: Any) -> str:
        calls.append(command)
        if command[1] == "build":
            Path(command[command.index("--iidfile") + 1]).write_text("sha256:" + "a" * 64)
        if command[1] == "inspect":
            return json.dumps([deepcopy(policy())])
        if command[1] == "start":
            if interrupted:
                raise KeyboardInterrupt
            raise feasibility.ExperimentError("fixture failed")
        return ""

    monkeypatch.setattr(shutil, "which", lambda _: "/fake/docker")
    monkeypatch.setattr(feasibility, "run_logged", fake)
    with pytest.raises(KeyboardInterrupt if interrupted else feasibility.ExperimentError):
        feasibility.container(tmp_path)
    assert calls[-1][1:3] == ["rm", "--force"]
    assert calls[-1][-1] == next(call[3] for call in calls if call[1] == "create")


def test_create_timeout_still_attempts_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    (tmp_path / "diagnostics").mkdir()

    def fake(command: list[str], log: Path, timeout: float, **kwargs: Any) -> str:
        calls.append(command)
        if command[1] == "build":
            Path(command[command.index("--iidfile") + 1]).write_text("sha256:" + "a" * 64)
        if command[1] == "create":
            raise feasibility.ExperimentError("create timeout")
        return ""

    monkeypatch.setattr(shutil, "which", lambda _: "/fake/docker")
    monkeypatch.setattr(feasibility, "run_logged", fake)
    with pytest.raises(feasibility.ExperimentError, match="create timeout"):
        feasibility.container(tmp_path)
    assert calls[-1][1:3] == ["rm", "--force"]
