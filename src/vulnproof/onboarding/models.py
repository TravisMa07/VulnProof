"""Bounded command/application profiles. Profile data never executes on the host."""

import re
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from vulnproof.models.common import Contract, ImageId, RelativePath, Sha256
from vulnproof.runner.repository import Wheel

Argument = Annotated[str, Field(min_length=1, max_length=8192)]
Command = Annotated[tuple[Argument, ...], Field(min_length=1, max_length=64)]


class Seed(Contract):
    path: RelativePath
    text: str = Field(max_length=65536)


class Header(Contract):
    name: str = Field(min_length=1, max_length=128)
    value: str = Field(max_length=8192)

    @field_validator("name")
    @classmethod
    def header_name(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", value) or value.lower() in {
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "upgrade",
            "expect",
        }:
            raise ValueError("Unsupported HTTP header")
        return value

    @field_validator("value")
    @classmethod
    def header_value(cls, value: str) -> str:
        if not value.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Expected printable ASCII header value")
        return value


class HttpStep(Contract):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] = "GET"
    target: str = Field(min_length=1, max_length=16384)
    headers: tuple[Header, ...] = Field(default=(), max_length=32)
    body: str | None = Field(default=None, max_length=16384)
    expected_status: int = Field(ge=100, le=599)
    expected_body_sha256: Sha256

    @field_validator("target")
    @classmethod
    def local_target(cls, value: str) -> str:
        if (
            not value.startswith("/")
            or value.startswith("//")
            or not value.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 for c in value)
            or "#" in value
        ):
            raise ValueError("Expected encoded local request target")
        return value

    @model_validator(mode="after")
    def unique_headers(self) -> Self:
        if len({h.name.lower() for h in self.headers}) != len(self.headers):
            raise ValueError("Duplicate HTTP header")
        return self


class Readiness(Contract):
    target: str = "/"
    status: int = Field(default=200, ge=100, le=599)
    timeout_seconds: int = Field(default=10, ge=1, le=20)

    @field_validator("target")
    @classmethod
    def target_path(cls, value: str) -> str:
        return HttpStep.local_target(value)


class Application(Contract):
    schema_version: Literal["1.0"] = "1.0"
    kind: Literal["http", "harness"]
    command: Command
    workdir: RelativePath | None = None
    wheels: tuple[Wheel, ...] = Field(default=(), max_length=128)
    environment: dict[str, str] = Field(default_factory=dict, max_length=32)
    image_directories: tuple[RelativePath, ...] = Field(default=(), max_length=32)
    seeds: tuple[Seed, ...] = Field(default=(), max_length=32)
    initialize: tuple[Command, ...] = Field(default=(), max_length=8)
    port: int = Field(default=8000, ge=1024, le=65535)
    readiness: Readiness = Field(default_factory=Readiness)
    controls: tuple[HttpStep, ...] = Field(default=(), max_length=16)

    @model_validator(mode="after")
    def bounded(self) -> Self:
        if len(self.model_dump_json().encode()) > 24576:
            raise ValueError("Application profile exceeds the 24 KiB budget")
        if any("\0" in arg for command in (self.command, *self.initialize) for arg in command):
            raise ValueError("Command arguments cannot contain NUL")
        if self.kind == "http" and not self.controls:
            raise ValueError("HTTP application requires a legitimate control")
        if self.kind == "harness" and self.controls:
            raise ValueError("Harness does not establish HTTP observations")
        if len({w.filename for w in self.wheels}) != len(self.wheels):
            raise ValueError("Duplicate wheels")
        if len({s.path for s in self.seeds}) != len(self.seeds):
            raise ValueError("Duplicate seed path")
        for seed in self.seeds:
            if any(
                PurePosixPath(seed.path).is_relative_to(other.path)
                for other in self.seeds
                if seed != other
            ):
                raise ValueError("Overlapping seed paths")
        for name, value in self.environment.items():
            if (
                not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
                or name in {"HOME", "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH"}
                or len(value) > 8192
                or "\0" in value
            ):
                raise ValueError("Invalid application environment")
        return self


class OnboardingPlan(Contract):
    schema_version: Literal["1.0"] = "1.0"
    profile: Literal["application-onboarding-v1"] = "application-onboarding-v1"
    scan_sha256: Sha256
    source_fingerprint: Sha256
    configuration_sha256: Sha256 | None
    application: Application | None
    observations: tuple[dict[str, str], ...]
    gaps: tuple[str, ...]
    execution_authorized: Literal[False] = False


class PreparedApplication(Contract):
    schema_version: Literal["1.0"] = "1.0"
    profile: Literal["prepared-application-v1"] = "prepared-application-v1"
    plan_sha256: Sha256
    scan_sha256: Sha256
    source_fingerprint: Sha256
    app_image: ImageId
    observer_image: ImageId
    worker_sha256: Sha256
    recipe_sha256: Sha256
    base_image: str
    application: Application
    execution_authorized: Literal[False] = False


class CallbackObservation(Contract):
    method: Literal["GET", "POST"]
    path: str = Field(max_length=128)
    body_bytes: int = Field(ge=0, le=65536)
    body_sha256: Sha256


class HttpObservation(Contract):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]
    target: str = Field(max_length=16384)
    request_body_bytes: int = Field(ge=0, le=65536)
    request_body_sha256: Sha256
    request_headers_sha256: Sha256
    status: int = Field(ge=100, le=599)
    body_bytes: int = Field(ge=0, le=65536)
    body_sha256: Sha256
    truncated: Literal[False]
    matched: bool


class ObserverResult(Contract):
    outcome: Literal["completed", "failed"]
    reason: str
    ready: bool
    controls: tuple[HttpObservation, ...] = Field(max_length=16)
    callbacks: tuple[CallbackObservation, ...] = Field(max_length=32)
    egress_probe_connected: bool
    runtime_checks: dict[str, bool]
