"""Validation observations preserve failures independently of oracle evidence."""

import base64
import hashlib
import re
from typing import Literal, Self

from pydantic import Field, model_validator

from vulnproof.models import Reason
from vulnproof.models.common import Contract, Identifier, Sha256
from vulnproof.runner.models import DockerCommand, PreparedImage, Recipe

PROFILE: Literal["fixture-cwe22-validation-v1"] = "fixture-cwe22-validation-v1"
DOCUMENT_SHA256 = "62527d78c70ef8f47bffc15e6c5352dd6f0a751b97f620013e52c25a138aa62f"


class Approval(Contract):
    schema_version: Literal["1.0"]
    profile: Literal["fixture-cwe22-validation-v1"]
    recipes: tuple[Recipe, ...]


class Preparation(Contract):
    schema_version: Literal["1.0"]
    profile: Literal["fixture-cwe22-validation-v1"]
    approval_sha256: Sha256
    images: tuple[PreparedImage, ...] = Field(min_length=1, max_length=2)

    @model_validator(mode="after")
    def unique_images(self) -> Self:
        if len({i.fixture_id for i in self.images}) != len(self.images):
            raise ValueError("duplicate image fixture")
        return self


class Response(Contract):
    status: int = Field(ge=100, le=599)
    body_base64: str = Field(max_length=87384)

    @property
    def body(self) -> bytes:
        return base64.b64decode(self.body_base64, validate=True)

    @model_validator(mode="after")
    def bounded_body(self) -> Self:
        if len(self.body) > 65536:
            raise ValueError("response exceeds bound")
        return self


class Canary(Contract):
    path: str
    initially_absent: Literal[True]
    body_base64: str

    @property
    def body(self) -> bytes:
        return base64.b64decode(self.body_base64, validate=True)

    @model_validator(mode="after")
    def fresh_marker(self) -> Self:
        if not re.fullmatch(r"/tmp/vulnproof/[0-9a-f]{32}\.txt", self.path) or not re.fullmatch(
            rb"VulnProof:[0-9a-f]{64}\n", self.body
        ):
            raise ValueError("invalid fresh canary shape")
        return self


class Probe(Response):
    kind: Literal["parent_traversal", "absolute_path"]


class Driver(Contract):
    schema_version: Literal["1.0"]
    profile: Literal["fixture-cwe22-validation-v1"]
    outcome: Literal["completed", "failed"]
    diagnostics_passed: bool
    control: Response | None
    canary: Canary | None
    probes: tuple[Probe, ...]
    errors: tuple[Identifier, ...]

    @property
    def control_valid(self) -> bool:
        return (
            self.control is not None
            and self.control.status == 200
            and hashlib.sha256(self.control.body).hexdigest() == DOCUMENT_SHA256
        )

    @property
    def observed(self) -> bool:
        return self.canary is not None and any(
            p.status == 200 and p.body == self.canary.body for p in self.probes
        )

    @model_validator(mode="after")
    def sequence(self) -> Self:
        if (
            tuple(p.kind for p in self.probes)
            != ("parent_traversal", "absolute_path")[: len(self.probes)]
        ):
            raise ValueError("probe order or cardinality changed")
        if self.probes and (
            not self.control_valid or not self.diagnostics_passed or self.canary is None
        ):
            raise ValueError("probes require passing controls and fresh canary")
        if self.outcome == "completed" and (
            not self.control_valid
            or not self.diagnostics_passed
            or self.canary is None
            or len(self.probes) != 2
            or self.errors
        ):
            raise ValueError("completed validation requires all bounded checks")
        if self.outcome == "failed" and not self.errors:
            raise ValueError("failed driver requires errors")
        return self


class Attempt(Contract):
    schema_version: Literal["1.0"]
    profile: Literal["fixture-cwe22-validation-v1"]
    attempt_id: Identifier
    fixture_id: Identifier
    image: PreparedImage
    preparation_sha256: Sha256
    approval_sha256: Sha256
    plan_sha256: Sha256
    finding_id: Identifier
    candidate_result_id: Identifier
    path_id: Identifier
    execution_authorized: Literal[True]
    authorization_scope: Literal["fixture_cwe22_validation_only"]
    policy_verified: bool
    execution: Literal[
        "not_started", "completed", "failed", "timed_out", "output_limit", "interrupted"
    ]
    cleanup: Literal["not_needed", "verified_absent", "unverified"]
    exit_code: int | None
    oom_killed: bool | None
    driver: Driver | None
    commands: tuple[DockerCommand, ...]
    reasons: tuple[Reason, ...]

    @model_validator(mode="after")
    def completion(self) -> Self:
        if self.fixture_id != self.image.fixture_id:
            raise ValueError("image fixture mismatch")
        if self.execution == "completed" and (
            not self.policy_verified
            or self.driver is None
            or self.driver.outcome != "completed"
            or self.exit_code != 0
            or self.oom_killed is not False
        ):
            raise ValueError("completed execution requires successful inspected driver")
        return self
