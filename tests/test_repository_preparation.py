import json
import os
import zipfile
from pathlib import Path
from typing import Any

import pytest

from vulnproof.cli import main
from vulnproof.provenance.filesystem import open_root, scan_tree
from vulnproof.provenance.models import fingerprint
from vulnproof.runner import repository as preparation
from vulnproof.runner.docker import RunnerFailure

IMAGE = "sha256:" + "a" * 64


def inputs(root: Path, module: str = "exports/web.py") -> tuple[Path, Path, Path]:
    scan = root / "scan"
    source = scan / "snapshot"
    (source / module).parent.mkdir(parents=True)
    (source / module).write_text("raise RuntimeError('preparation must not import application')\n")
    (source / "Dockerfile").write_text("RUN deliberately-invalid-repository-build-command\n")
    (source / "setup.py").write_text("raise RuntimeError('must not execute setup.py')\n")
    (source / "manual.txt").write_text("synthetic document\n")
    with open_root(source) as fd:
        captured = scan_tree(fd)
    (scan / "scan.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "profile": "repository-import-v1",
                "outcome": "completed",
                "component": None,
                "files": [f.model_dump() for f in captured.files],
                "source_fingerprint": fingerprint(captured.files),
            }
        )
    )
    wheels = root / "wheels"
    wheels.mkdir()
    wheel = wheels / "preparation_demo-1.0-py3-none-any.whl"
    # A local test distribution; no package downloads, setup hooks, or runtime execution.
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("preparation_demo.py", "VALUE = 1\n")
        archive.writestr(
            "preparation_demo-1.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: preparation-demo\nVersion: 1.0\n",
        )
        archive.writestr(
            "preparation_demo-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr("preparation_demo-1.0.dist-info/RECORD", "")
    config = root / "image.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "entry_point": module + ":service",
                "platform": "linux/arm64",
                "wheels": [
                    {
                        "filename": wheel.name,
                        "sha256": preparation.sha(wheel.read_bytes()),
                    }
                ],
            }
        )
    )
    return scan, config, wheels


class FakeDocker:
    calls: list[list[str]]
    fail = False
    invalid = False
    mutate = False

    def __init__(self, socket: Path, root: Path, *, preparation: bool = False) -> None:
        self.root = root
        self.commands: list[Any] = []
        self.calls = []
        assert preparation

    def run(self, args: list[str], stage: str, *, timeout: float = 15) -> bytes:
        self.calls.append(args)
        assert args[0] in {"info", "build", "image"}
        if args[0] == "info":
            return json.dumps(
                {
                    "os": "linux",
                    "cpu": True,
                    "memory": True,
                    "swap": True,
                    "pids": True,
                    "security": [],
                }
            ).encode()
        if args[0] == "build":
            assert "--network=none" in args and "--platform" in args
            assert timeout == 600
            if self.fail:
                raise RunnerFailure("docker_command_failed", "Build failed")
            Path(args[args.index("--iidfile") + 1]).write_text(IMAGE)
            if self.mutate:
                (Path(args[-1]) / "requirements.lock").write_text("changed")
            return b""
        return json.dumps(
            [
                {
                    "Id": IMAGE,
                    "Os": "linux",
                    "Architecture": "arm64",
                    "Config": {
                        "User": "root" if self.invalid else "10001:10001",
                        "WorkingDir": "/application",
                        "Cmd": preparation.COMMAND,
                        "Healthcheck": {"Test": ["NONE"]},
                    },
                }
            ]
        ).encode()


@pytest.fixture
def docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preparation, "DockerClient", FakeDocker)


def test_prepare_records_source_and_recipe_without_import(tmp_path: Path, docker: None) -> None:
    scan, config, wheels = inputs(tmp_path)
    output = tmp_path / "prepared"
    receipt = preparation.prepare_repository_image(
        scan, config, wheels, Path("/docker.sock"), output
    )
    assert receipt.image_id == IMAGE
    assert receipt.configuration_sha256 == preparation.sha(config.read_bytes())
    assert (
        receipt.source_fingerprint
        == json.loads((scan / "scan.json").read_bytes())["source_fingerprint"]
    )
    assert not receipt.execution_authorized and not receipt.application_started
    assert receipt.entry_point_file == "exports/web.py"
    context = output / "work/context"
    assert (context / "source/manual.txt").read_text() == "synthetic document\n"
    assert (context / "Dockerfile").read_bytes() == preparation.recipe()
    assert preparation.recipe().index(b"pip --isolated check") < preparation.recipe().index(
        b"COPY source/"
    )
    assert json.loads((output / "preparation.json").read_bytes())["outcome"] == "completed"
    assert (
        preparation.RepositoryImage.model_validate_json(
            (output / "prepared-image.json").read_bytes()
        )
        == receipt
    )
    with pytest.raises(FileExistsError):
        preparation.prepare_repository_image(scan, config, wheels, Path("/docker.sock"), output)


@pytest.mark.parametrize("change", ["wheel", "source", "entry", "duplicate", "escape", "unknown"])
def test_invalid_inputs_never_publish_success(tmp_path: Path, docker: None, change: str) -> None:
    scan, config, wheels = inputs(tmp_path)
    data = json.loads(config.read_bytes())
    if change == "wheel":
        data["wheels"][0]["sha256"] = "0" * 64
    elif change == "source":
        (scan / "snapshot/exports/web.py").write_text("changed\n")
    elif change == "entry":
        data["entry_point"] = "missing.py:app"
    elif change == "duplicate":
        data["wheels"] *= 2
    elif change == "escape":
        data["wheels"][0]["filename"] = "../outside.whl"
    else:
        data["command"] = "unexpected"
    config.write_text(json.dumps(data))
    output = tmp_path / "prepared"
    with pytest.raises((RunnerFailure, ValueError)):
        preparation.prepare_repository_image(scan, config, wheels, Path("/docker.sock"), output)
    assert not (output / "prepared-image.json").exists()


@pytest.mark.parametrize("fault", ["fail", "invalid", "mutate"])
def test_build_failures_retain_diagnostics(
    tmp_path: Path, docker: None, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    scan, config, wheels = inputs(tmp_path)
    monkeypatch.setattr(FakeDocker, fault, True)
    output = tmp_path / "prepared"
    with pytest.raises(RunnerFailure):
        preparation.prepare_repository_image(scan, config, wheels, Path("/docker.sock"), output)
    assert not (output / "prepared-image.json").exists()
    assert json.loads((output / "preparation.json").read_bytes())["outcome"] == "failed"


def test_output_inside_evidence_rejected(tmp_path: Path, docker: None) -> None:
    scan, config, wheels = inputs(tmp_path)
    with pytest.raises(RunnerFailure, match="separate"):
        preparation.prepare_repository_image(
            scan, config, wheels, Path("/docker.sock"), scan / "new"
        )


def test_cli_and_missing_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    scan, config, wheels = inputs(tmp_path)
    monkeypatch.setenv("PATH", "")
    assert (
        main(
            [
                "prepare-repository-image",
                "--scan",
                str(scan),
                "--config",
                str(config),
                "--wheelhouse",
                str(wheels),
                "--docker-socket",
                "/docker.sock",
                "--output",
                str(tmp_path / "prepared"),
            ]
        )
        == 2
    )
    assert "docker_missing" in capsys.readouterr().err
    assert json.loads((tmp_path / "prepared/preparation.json").read_bytes())["outcome"] == "failed"


@pytest.mark.skipif(
    not os.environ.get("VULNPROOF_PREPARATION_DOCKER_SOCKET"),
    reason="opt-in real Docker preparation",
)
@pytest.mark.parametrize("module", ["exports/web.py", "unfamiliar/server.py"])
def test_real_preparation(tmp_path: Path, module: str) -> None:
    scan, config, wheels = inputs(tmp_path, module)
    data = json.loads(config.read_bytes())
    data["platform"] = os.environ.get("VULNPROOF_PREPARATION_PLATFORM", "linux/amd64")
    config.write_text(json.dumps(data))
    output = tmp_path / "prepared"
    receipt = preparation.prepare_repository_image(
        scan,
        config,
        wheels,
        Path(os.environ["VULNPROOF_PREPARATION_DOCKER_SOCKET"]),
        output,
    )
    assert receipt.entry_point_file == module
    assert receipt.image_id.startswith("sha256:")
    assert not receipt.application_started


def test_interruption_records_failure(
    tmp_path: Path, docker: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan, config, wheels = inputs(tmp_path)

    def interrupt(self: FakeDocker, args: list[str], stage: str, *, timeout: float = 15) -> bytes:
        raise KeyboardInterrupt

    monkeypatch.setattr(FakeDocker, "run", interrupt)
    output = tmp_path / "prepared"
    with pytest.raises(KeyboardInterrupt):
        preparation.prepare_repository_image(scan, config, wheels, Path("/docker.sock"), output)
    assert json.loads((output / "preparation.json").read_bytes())["outcome"] == "interrupted"
    assert not (output / "prepared-image.json").exists()


def test_symlink_wheel_rejected(tmp_path: Path, docker: None) -> None:
    scan, config, wheels = inputs(tmp_path)
    wheel = next(wheels.iterdir())
    outside = tmp_path / "outside.whl"
    wheel.rename(outside)
    wheel.symlink_to(outside)
    with pytest.raises(OSError):
        preparation.prepare_repository_image(
            scan, config, wheels, Path("/docker.sock"), tmp_path / "prepared"
        )


@pytest.mark.parametrize("reply", [b"null", b"[{}]", b'[{"Config": null}]'])
def test_malformed_inspection_is_explicit_failure(
    tmp_path: Path, docker: None, monkeypatch: pytest.MonkeyPatch, reply: bytes
) -> None:
    scan, config, wheels = inputs(tmp_path)
    original = FakeDocker.run

    def malformed(self: FakeDocker, args: list[str], stage: str, *, timeout: float = 15) -> bytes:
        return reply if stage == "inspect-image" else original(self, args, stage, timeout=timeout)

    monkeypatch.setattr(FakeDocker, "run", malformed)
    output = tmp_path / "prepared"
    with pytest.raises(RunnerFailure):
        preparation.prepare_repository_image(scan, config, wheels, Path("/docker.sock"), output)
    assert json.loads((output / "preparation.json").read_bytes())["failure_code"]
    assert not (output / "prepared-image.json").exists()


@pytest.mark.skipif(
    not os.environ.get("VULNPROOF_PREPARATION_DOCKER_SOCKET"),
    reason="opt-in real Docker preparation",
)
@pytest.mark.parametrize("broken", ["missing_dependency", "invalid_archive"])
def test_real_dependency_rejection(tmp_path: Path, broken: str) -> None:
    scan, config, wheels = inputs(tmp_path)
    wheel = next(wheels.iterdir())
    if broken == "invalid_archive":
        wheel.write_bytes(b"not a wheel archive")
    else:
        with zipfile.ZipFile(wheel) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        members["preparation_demo-1.0.dist-info/METADATA"] += (
            b"Requires-Dist: absent-vulnproof-test-package==99.0\n"
        )
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, content in members.items():
                archive.writestr(name, content)
    data = json.loads(config.read_bytes())
    data["platform"] = os.environ.get("VULNPROOF_PREPARATION_PLATFORM", "linux/amd64")
    data["wheels"][0]["sha256"] = preparation.sha(wheel.read_bytes())
    config.write_text(json.dumps(data))
    output = tmp_path / "prepared"
    with pytest.raises(RunnerFailure, match="Docker operation failed"):
        preparation.prepare_repository_image(
            scan,
            config,
            wheels,
            Path(os.environ["VULNPROOF_PREPARATION_DOCKER_SOCKET"]),
            output,
        )
    assert not (output / "prepared-image.json").exists()
    assert json.loads((output / "preparation.json").read_bytes())["outcome"] == "failed"
