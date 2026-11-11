"""Prepare a source-bound application image without starting the application."""

import hashlib
import json
import re
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from vulnproof.artifacts import read_local
from vulnproof.models.common import Contract, RelativePath, Sha256, relative_path
from vulnproof.planning.repository import unique_fields
from vulnproof.provenance.filesystem import open_root, scan_tree
from vulnproof.provenance.models import fingerprint
from vulnproof.static.repository import ScanInput

from .docker import DockerClient, RunnerFailure
from .engine import inspection, publish
from .profile import DAEMON_FORMAT, verify_daemon

BASE = "python:3.14.10-slim-bookworm@sha256:516b51cb9db2ef061e465c803e50f64361b82cefd91e525b889b967b83e83527"
COMMAND = ["python", "-I", "-c", "raise SystemExit('Prepared image; use an authorized runner')"]
MAX_WHEEL = 64 * 1024 * 1024
MAX_WHEELS = 256 * 1024 * 1024


class Wheel(Contract):
    filename: str = Field(min_length=1, max_length=200)
    sha256: Sha256

    @field_validator("filename")
    @classmethod
    def wheel_filename(cls, value: str) -> str:
        # A filename, never a pip option, URL, directory, or source distribution.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*\.whl", value):
            raise ValueError("Expected a wheel filename")
        return value


class ImageConfiguration(Contract):
    schema_version: Literal["1.0"]
    entry_point: str = Field(max_length=512)
    platform: Literal["linux/amd64", "linux/arm64"]
    wheels: tuple[Wheel, ...] = Field(min_length=1, max_length=128)

    @field_validator("entry_point")
    @classmethod
    def application(cls, value: str) -> str:
        file, separator, symbol = value.partition(":")
        if not separator or not relative_path(file).endswith(".py") or not symbol.isidentifier():
            raise ValueError("Expected captured Python file:application_symbol")
        return value

    @model_validator(mode="after")
    def distinct(self) -> Self:
        if len({w.filename for w in self.wheels}) != len(self.wheels):
            raise ValueError("Duplicate wheel filename")
        return self


class RepositoryImage(Contract):
    schema_version: Literal["1.1"] = "1.1"
    driver_sha256: Sha256
    profile: Literal["repository-image-v1"] = "repository-image-v1"
    scan_sha256: Sha256
    source_fingerprint: Sha256
    configuration_sha256: Sha256
    configuration: ImageConfiguration
    recipe_sha256: Sha256
    requirements_sha256: Sha256
    base_image: str
    image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    source_directory: Literal["/application"] = "/application"
    entry_point_file: RelativePath
    execution_authorized: Literal[False] = False
    application_started: Literal[False] = False


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def driver_bytes() -> bytes:
    return files("vulnproof.runner").joinpath("control_driver.py").read_bytes()


def verify_repository_image(observed: dict[str, Any], record: RepositoryImage) -> None:
    config = observed.get("Config")
    if not isinstance(config, dict) or not isinstance(config.get("Healthcheck"), dict):
        raise RunnerFailure("image_policy_mismatch", "Missing image configuration")
    if (
        observed.get("Id") != record.image_id
        or f"{observed.get('Os')}/{observed.get('Architecture')}" != record.configuration.platform
        or config.get("User") != "10001:10001"
        or config.get("WorkingDir") != "/application"
        or config.get("Cmd") != COMMAND
        or config.get("Entrypoint")
        or config.get("Volumes")
        or config.get("OnBuild")
        or config.get("Healthcheck", {}).get("Test") != ["NONE"]
    ):
        raise RunnerFailure("image_policy_mismatch", "Prepared image failed configuration checks")


def recipe() -> bytes:
    # Install before copying source: Python cannot load checkout modules during installation.
    return (
        f"FROM {BASE}\n"
        "ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1\n"
        "WORKDIR /opt/vulnproof\n"
        "COPY wheels/ /opt/vulnproof/wheels/\n"
        "COPY requirements.lock /opt/vulnproof/requirements.lock\n"
        "RUN python -I -m pip --isolated install --no-index --no-deps --no-cache-dir "
        "--only-binary=:all: --require-hashes -r requirements.lock "
        "&& python -I -m pip --isolated check\n"
        "COPY control_driver.py /opt/vulnproof/control_driver.py\n"
        "COPY source/ /application/\n"
        "WORKDIR /application\n"
        "USER 10001:10001\n"
        "ENTRYPOINT []\n"
        "HEALTHCHECK NONE\n"
        f"CMD {json.dumps(COMMAND)}\n"
    ).encode()


def prepare_repository_image(
    scan: Path, config: Path, wheelhouse: Path, socket: Path, output: Path
) -> RepositoryImage:
    scan, config, wheelhouse, output = (p.absolute() for p in (scan, config, wheelhouse, output))
    if any(
        a.resolve().is_relative_to(b.resolve())
        for root in (scan, wheelhouse, config)
        for a, b in ((output, root), (root, output))
    ):
        raise RunnerFailure("invalid_output", "Preparation output must be separate from inputs")
    try:
        scan_bytes = read_local(scan, "scan.json", 16 * 1024 * 1024)
        manifest = ScanInput.model_validate_json(scan_bytes)
        if fingerprint(manifest.files) != manifest.source_fingerprint:
            raise ValueError("Inconsistent source manifest")
        config_bytes = read_local(config.parent, config.name, 1024 * 1024)
        json.loads(config_bytes, object_pairs_hook=unique_fields)
        selected = ImageConfiguration.model_validate_json(config_bytes)
        entry_file = selected.entry_point.partition(":")[0]
        if entry_file not in {f.path for f in manifest.files}:
            raise ValueError("Entry point must be captured source")
        wheel_bytes = {}
        total = 0
        for wheel in selected.wheels:
            data = read_local(wheelhouse, wheel.filename, MAX_WHEEL)
            total += len(data)
            if total > MAX_WHEELS or sha(data) != wheel.sha256:
                raise ValueError("Wheel hash mismatch or total wheel limit exceeded")
            wheel_bytes[wheel.filename] = data
    except ValueError as exc:
        raise RunnerFailure(
            "invalid_preparation_input",
            "Invalid scan, entry point, configuration, wheel hash, or input limit",
        ) from exc

    output.mkdir(mode=0o700)
    (output / "diagnostics").mkdir(mode=0o700)
    context = output / "work/context"
    source = context / "source"
    source.mkdir(parents=True)
    client: DockerClient | None = None
    outcome = "failed"
    failure_code: str | None = None
    try:
        with open_root(scan / "snapshot") as fd:
            copied = scan_tree(fd, source)
        if copied.files != manifest.files or copied.excluded_paths:
            raise RunnerFailure("source_changed", "Snapshot differs from retained scan")
        (context / "wheels").mkdir()
        for name, data in wheel_bytes.items():
            (context / "wheels" / name).write_bytes(data)
        requirements = "".join(
            f"/opt/vulnproof/wheels/{w.filename} --hash=sha256:{w.sha256}\n"
            for w in selected.wheels
        ).encode()
        build_recipe = recipe()
        driver = driver_bytes()
        (context / "control_driver.py").write_bytes(driver)
        (context / "Dockerfile").write_bytes(build_recipe)
        (context / "requirements.lock").write_bytes(requirements)
        client = DockerClient(socket, output, preparation=True)
        verify_daemon(json.loads(client.run(["info", DAEMON_FORMAT], "daemon")))
        iid = output / "image.iid"
        client.run(
            [
                "build",
                "--pull",
                "--network=none",
                "--platform",
                selected.platform,
                "--iidfile",
                str(iid),
                str(context),
            ],
            "build-repository",
            timeout=600,
        )
        image_id = read_local(output, "image.iid", 128).decode("ascii").strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise RunnerFailure("invalid_image_id", "Docker did not return an immutable image ID")
        with open_root(source) as fd:
            after = scan_tree(fd)
        expected = {
            "Dockerfile": build_recipe,
            "requirements.lock": requirements,
            "control_driver.py": driver,
        }
        expected.update({"wheels/" + name: data for name, data in wheel_bytes.items()})
        if (
            after.files != manifest.files
            or after.excluded_paths
            or any(read_local(context, name, MAX_WHEEL) != data for name, data in expected.items())
        ):
            raise RunnerFailure("build_inputs_changed", "Private build inputs changed")
        if (
            read_local(scan, "scan.json", 16 * 1024 * 1024) != scan_bytes
            or read_local(config.parent, config.name, 1024 * 1024) != config_bytes
        ):
            raise RunnerFailure("preparation_inputs_changed", "Preparation metadata changed")
        record = RepositoryImage(
            driver_sha256=sha(driver),
            scan_sha256=sha(scan_bytes),
            source_fingerprint=manifest.source_fingerprint,
            configuration_sha256=sha(config_bytes),
            configuration=selected,
            recipe_sha256=sha(build_recipe),
            requirements_sha256=sha(requirements),
            base_image=BASE,
            image_id=image_id,
            entry_point_file=entry_file,
        )
        verify_repository_image(
            inspection(client.run(["image", "inspect", image_id], "inspect-image")), record
        )
        publish(output / "prepared-image.json", record.model_dump_json(indent=2) + "\n")
        outcome = "completed"
        return record
    except KeyboardInterrupt:
        outcome = "interrupted"
        failure_code = "preparation_interrupted"
        raise
    except (OSError, ValueError) as exc:
        failure_code = getattr(exc, "code", "preparation_failed")
        if isinstance(exc, (RunnerFailure, OSError)):
            raise
        raise RunnerFailure(
            "preparation_failed", "Preparation evidence or Docker response invalid"
        ) from exc
    finally:
        publish(
            output / "preparation.json",
            json.dumps(
                {
                    "schema_version": "1.0",
                    "outcome": outcome,
                    "failure_code": failure_code,
                    "scan_sha256": sha(scan_bytes),
                    "configuration_sha256": sha(config_bytes),
                    "source_fingerprint": manifest.source_fingerprint,
                    "commands": [c.model_dump(mode="json") for c in client.commands]
                    if client
                    else [],
                },
                indent=2,
            )
            + "\n",
        )
