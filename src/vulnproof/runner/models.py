"""Diagnostic attempt observations are distinct from vulnerability assessments."""

from typing import Literal, Self

from pydantic import Field, model_validator

from vulnproof.models import Artifact, Reason
from vulnproof.models.common import Contract, Identifier, ImageId, Sha256
from vulnproof.planning.models import ExecutionRequirements

PROFILE = "fixture-diagnostics-v1"
CHECKS = (
    "non_root",
    "no_new_privileges",
    "zero_capabilities",
    "read_only_root",
    "root_write_denied",
    "temporary_write",
    "only_loopback",
    "debug_disabled",
    "legitimate_download",
)


class Recipe(Contract):
    fixture_id: Identifier
    inputs: dict[str, Sha256]


class RunnerApproval(Contract):
    schema_version: Literal["1.0"]
    profile: Literal["fixture-diagnostics-v1"]
    recipes: tuple[Recipe, ...]


class PreparedImage(Contract):
    fixture_id: Identifier
    source_fingerprint: Sha256
    recipe_sha256: Sha256
    image_id: ImageId


class PreparationRecord(Contract):
    schema_version: Literal["1.0"]
    profile: Literal["fixture-diagnostics-v1"]
    approval_sha256: Sha256
    images: tuple[PreparedImage, ...] = Field(min_length=1, max_length=2)

    @model_validator(mode="after")
    def unique_images(self) -> Self:
        if len({i.fixture_id for i in self.images}) != len(self.images):
            raise ValueError("preparation must contain unique fixture identities")
        return self


class DockerCommand(Contract):
    stage: Identifier
    outcome: Literal[
        "completed", "failed", "timed_out", "output_limit", "interrupted", "start_failed"
    ]
    return_code: int | None
    duration_seconds: float = Field(ge=0)
    log: Artifact


class DriverReport(Contract):
    schema_version: Literal["1.0"]
    profile: Literal["fixture-diagnostics-v1"]
    checks: dict[str, bool]

    @model_validator(mode="after")
    def all_checks(self) -> Self:
        if set(self.checks) != set(CHECKS) or not all(self.checks.values()):
            raise ValueError("driver must report exactly the required passing checks")
        return self


class RunnerAttempt(Contract):
    schema_version: Literal["1.0"]
    profile: Literal["fixture-diagnostics-v1"]
    attempt_id: Identifier
    container_name: Identifier
    fixture_id: Identifier
    image_id: ImageId
    source_fingerprint: Sha256
    plan_sha256: Sha256
    preparation_sha256: Sha256
    approval_sha256: Sha256
    finding_id: Identifier
    candidate_result_id: Identifier
    path_ids: tuple[Identifier, ...]
    execution_authorized: Literal[True]
    authorization_scope: Literal["fixture_diagnostics_only"] = "fixture_diagnostics_only"
    scanner_source_state: Literal["unverified"] = "unverified"
    requested: ExecutionRequirements
    policy_verified: bool
    execution: Literal[
        "not_started", "completed", "failed", "timed_out", "output_limit", "interrupted"
    ]
    cleanup: Literal["not_needed", "verified_absent", "unverified"]
    container_exit_code: int | None = None
    oom_killed: bool | None = None
    driver: DriverReport | None = None
    commands: tuple[DockerCommand, ...]
    reasons: tuple[Reason, ...]

    @model_validator(mode="after")
    def completed_diagnostics(self) -> Self:
        if self.execution == "completed" and (
            not self.policy_verified
            or self.driver is None
            or self.container_exit_code != 0
            or self.oom_killed is not False
        ):
            raise ValueError("completed diagnostics require checked policy, state, and driver")
        return self
