"""Authorized repository controls, with no vulnerability probes or assessments."""

import json
from pathlib import Path
from typing import Any, Literal, Self
from uuid import uuid4

from pydantic import Field, model_validator

from vulnproof.artifacts import read_local
from vulnproof.correlation.engine import MAX_DOCUMENT_BYTES
from vulnproof.investigation.contracts import (
    ApplicationProfile,
    ExecutionContext,
    invocation_from_request,
)
from vulnproof.models import Reason
from vulnproof.models.common import Contract, ImageId, Sha256
from vulnproof.planning.engine import planning_catalog
from vulnproof.planning.models import ExecutionRequirements
from vulnproof.planning.repository import plan_repository, unique_fields

from .control_driver import CHECKS, RESPONSE_LIMIT, request_target
from .docker import DockerClient, RunnerFailure
from .engine import cleanup_container, inspection, publish
from .models import DockerCommand
from .profile import DAEMON_FORMAT, create_args, verify_container, verify_daemon
from .repository import BASE, RepositoryImage, driver_bytes, recipe, sha, verify_repository_image


class ControlObservation(Contract):
    schema_version: Literal["1.0"]
    profile: Literal["repository-control-v1"]
    checks: dict[str, bool]
    application_started: bool
    control: Literal["passed", "failed", "not_run"]
    reason: Literal[
        "restriction_check_failed",
        "dependency_missing",
        "application_import_failed",
        "application_symbol_missing",
        "unsupported_application",
        "unsupported_validator",
        "debug_enabled",
        "server_start_failed",
        "startup_timeout",
        "request_failed",
        "response_limit",
        "status_mismatch",
        "body_mismatch",
        "control_matched",
    ]
    status: int | None = Field(default=None, ge=100, le=599)
    body_sha256: Sha256 | None = None
    body_bytes: int | None = Field(default=None, ge=0, le=RESPONSE_LIMIT + 1)
    truncated: bool = False
    validation: dict[str, Any] | None = None

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.application_started or self.control != "not_run":
            if set(self.checks) != set(CHECKS) or not all(self.checks.values()):
                raise ValueError("Application execution requires all restriction checks")
        if self.control != "not_run" and not self.application_started:
            raise ValueError("Control requires started application")
        if self.control == "passed" and (
            self.status != 200
            or self.body_sha256 is None
            or self.body_bytes is None
            or self.body_bytes > RESPONSE_LIMIT
            or self.truncated
            or self.reason != "control_matched"
        ):
            raise ValueError("Passing control requires a complete response")
        if (self.reason == "control_matched") != (self.control == "passed"):
            raise ValueError("Control outcome and reason disagree")
        return self


class RepositoryControlAttempt(Contract):
    schema_version: Literal["1.0", "1.1", "1.2"] = "1.0"
    profile: Literal["repository-control-v1", "repository-validation-attempt-v1"] = (
        "repository-control-v1"
    )
    container_name: str
    image_id: ImageId
    source_fingerprint: Sha256
    plan_sha256: Sha256
    preparation_sha256: Sha256
    driver_sha256: Sha256
    finding_id: str
    candidate_result_id: str
    path_ids: tuple[str, ...]
    supporting_path_ids: tuple[str, ...]
    scanner_source_state: Literal["controlled_snapshot", "unverified"]
    execution_authorized: Literal[True] = True
    authorization_scope: Literal["repository_control_only", "repository_cwe22_validation"] = (
        "repository_control_only"
    )
    request: dict[str, str]
    http_request: dict[str, Any] | None = None
    context: ExecutionContext | None = None
    validator_id: str | None = None
    requested: ExecutionRequirements
    policy_verified: bool
    execution: Literal[
        "not_started", "completed", "failed", "timed_out", "output_limit", "interrupted"
    ]
    cleanup: Literal["not_needed", "verified_absent", "unverified"]
    container_exit_code: int | None
    oom_killed: bool | None
    driver: ControlObservation | None
    commands: tuple[DockerCommand, ...]
    reasons: tuple[Reason, ...]

    @model_validator(mode="after")
    def request_profile(self) -> Self:
        if (self.schema_version == "1.0" and self.http_request is not None) or (
            self.schema_version == "1.1" and self.http_request is None
        ):
            raise ValueError("Request profile requires attempt schema 1.1")
        if self.http_request is not None:
            target = request_target(self.http_request, self.http_request.get("control_value", ""))
            if target != self.request.get("request_target"):
                raise ValueError("Control request differs from request profile")
            for key in ("route", "query_key"):
                if key in self.request and self.request[key] != self.http_request[key]:
                    raise ValueError("Request binding differs from profile")
        if self.schema_version != "1.2" and self.validator_id is not None:
            raise ValueError("Validator identity requires attempt schema 1.2")
        if self.schema_version == "1.2" and (
            self.authorization_scope == "repository_cwe22_validation"
        ) != (self.validator_id is not None):
            raise ValueError("Validation attempt requires an explicit validator identity")
        if (self.schema_version == "1.2") != (self.context is not None):
            raise ValueError("Execution context requires attempt schema 1.2")
        if self.context is not None:
            app = self.context.application
            if (
                app.source_fingerprint != self.source_fingerprint
                or app.image_id != self.image_id
                or app.preparation_sha256 != self.preparation_sha256
                or app.entry_point != self.request.get("entry_point")
            ):
                raise ValueError("Application context differs from attempt provenance")
            invocation_request = {
                **self.request,
                "query_key": self.request.get("query_key", self.context.invocation.input_name),
            }
            if self.context.invocation != invocation_from_request(
                invocation_request, self.http_request
            ):
                raise ValueError("Invocation context differs from attempt request")
        return self

    @property
    def succeeded(self) -> bool:
        return (
            self.execution == "completed"
            and self.cleanup == "verified_absent"
            and self.driver is not None
            and self.driver.control == "passed"
        )

    @model_validator(mode="after")
    def completed(self) -> Self:
        if self.execution == "completed" and (
            not self.policy_verified
            or self.driver is None
            or self.driver.control == "not_run"
            or self.container_exit_code != 0
            or self.oom_killed is not False
        ):
            raise ValueError("Completed control requires checked policy, state, and observation")
        if (
            self.driver
            and self.driver.control == "passed"
            and self.driver.body_sha256 != self.request["body_sha256"]
        ):
            raise ValueError("Control hash differs from planned expected response")
        return self


def read(path: Path) -> bytes:
    return read_local(path.absolute().parent, path.name, MAX_DOCUMENT_BYTES)


def check_repository(
    *,
    scan: Path,
    investigation: Path,
    correlation: Path,
    discovery: Path,
    plan: Path,
    config: Path | None,
    preparation: Path,
    finding_id: str,
    socket: Path,
    output: Path,
    authorize_execution: bool,
    authorize_validation: bool = False,
) -> RepositoryControlAttempt:
    if not authorize_execution and not authorize_validation:
        raise RunnerFailure(
            "authorization_required",
            "Explicit authorization is required for this repository control",
        )
    try:
        plan_data = read(plan)
        supplied = json.loads(plan_data, object_pairs_hook=unique_fields)
        rebuilt = json.loads(plan_repository(scan, investigation, correlation, discovery, config))
        if supplied != rebuilt:
            raise RunnerFailure(
                "plan_mismatch", "Plan differs from retained evidence and configuration"
            )
        entries = [r for r in rebuilt["findings"] if r["finding_id"] == finding_id]
        if len(entries) != 1 or entries[0]["status"] != "draft":
            raise RunnerFailure(
                "finding_not_eligible", "Select one draft finding from the verified plan"
            )
        entry = entries[0]
        prepared_data = read(preparation)
        prepared_json = json.loads(prepared_data, object_pairs_hook=unique_fields)
        if prepared_json.get("schema_version") != "1.1" or "driver_sha256" not in prepared_json:
            raise RunnerFailure(
                "rebuild_required",
                "Rebuild the application image with the current preparation command",
            )
        image = RepositoryImage.model_validate_json(prepared_data)
        if image.driver_sha256 != sha(driver_bytes()) or image.recipe_sha256 != sha(recipe()):
            raise RunnerFailure(
                "rebuild_required",
                "Prepared image driver/recipe differs from installed version; rebuild",
            )
        requirements = "".join(
            f"/opt/vulnproof/wheels/{w.filename} --hash=sha256:{w.sha256}\n"
            for w in image.configuration.wheels
        ).encode()
        if (
            image.base_image != BASE
            or image.source_fingerprint != rebuilt["source_fingerprint"]
            or image.scan_sha256
            != sha(read_local(scan.absolute(), "scan.json", MAX_DOCUMENT_BYTES))
            or image.configuration.entry_point != entry["entry_point"]
            or image.entry_point_file != entry["entry_point"].partition(":")[0]
            or image.requirements_sha256 != sha(requirements)
        ):
            raise RunnerFailure(
                "image_source_mismatch",
                "Prepared source, dependencies, or entry point disagree with the plan",
            )
        request = {
            "entry_point": entry["entry_point"],
            "request_target": entry["control"]["request_target"],
            "body_sha256": entry["control"]["body_sha256"],
        }
        if authorize_validation:
            request.update(
                download_root=entry["download_root"],
                route=entry["route"],
                query_key=entry["query_key"],
            )
        driver_request: dict[str, Any] = dict(request)
        if entry.get("http_request") is not None:
            driver_request["http_request"] = entry["http_request"]
        if authorize_validation:
            driver_request.update(
                validator_id=entry["template_id"],
                validation=True,
                download_root=entry["download_root"],
                route=entry["route"],
                query_key=entry["query_key"],
            )
        payload = json.dumps(driver_request, separators=(",", ":"))
        if len(payload) > 32768:
            raise RunnerFailure("request_limit", "Control exceeds driver input bound")
        candidate = next(iter(entry["candidates"]))
        command = ["-I", "/opt/vulnproof/control_driver.py", payload]
        destination = output.absolute()
        roots = (scan, investigation, preparation.parent)
        inputs = (plan, correlation, discovery, preparation, *((config,) if config else ()))
        if any(destination.resolve().is_relative_to(p.resolve()) for p in roots) or any(
            p.resolve().is_relative_to(destination.resolve()) for p in (*roots, *inputs)
        ):
            raise RunnerFailure(
                "invalid_output", "Attempt output must be new and separate from evidence"
            )
        destination.mkdir(mode=0o700)
        (destination / "diagnostics").mkdir(mode=0o700)
    except RunnerFailure:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise RunnerFailure(
            "invalid_control_input",
            "Evidence or preparation is missing, changed, or inconsistent; output must be new",
        ) from exc

    name = "vulnproof-control-" + uuid4().hex
    publish(
        destination / "reservation.json",
        json.dumps({"container_name": name, "image_id": image.image_id}) + "\n",
    )
    client: DockerClient | None = None
    creation_attempted = policy_verified = interrupted = False
    execution: Literal[
        "not_started", "completed", "failed", "timed_out", "output_limit", "interrupted"
    ] = "not_started"
    cleanup: Literal["not_needed", "verified_absent", "unverified"] = "not_needed"
    driver: ControlObservation | None = None
    exit_code: int | None = None
    oom: bool | None = None
    reasons: list[Reason] = []
    try:
        client = DockerClient(socket, destination)
        verify_daemon(json.loads(client.run(["info", DAEMON_FORMAT], "daemon")))
        verify_repository_image(
            inspection(client.run(["image", "inspect", image.image_id], "image-inspect")), image
        )
        creation_attempted = True
        client.run(
            create_args(name, image.image_id, command=command, workdir="/application"),
            "create",
            timeout=30,
        )
        verify_container(
            inspection(client.run(["inspect", name], "container-inspect")),
            image.image_id,
            name,
            command=command,
            workdir="/application",
        )
        policy_verified = True
        execution = "failed"
        raw = client.run(["start", "--attach", name], "start", timeout=60)
        state = inspection(client.run(["inspect", name], "state"))["State"]
        if (
            state["Running"] is not False
            or type(state["ExitCode"]) is not int
            or type(state["OOMKilled"]) is not bool
        ):
            raise RunnerFailure(
                "invalid_container_state", "Container did not finish in an inspectable state"
            )
        exit_code, oom = state["ExitCode"], state["OOMKilled"]
        if exit_code != 0 or oom:
            raise RunnerFailure(
                "container_failed", "Container exit/OOM state failed control acceptance"
            )
        observation = ControlObservation.model_validate_json(raw, strict=True)
        if observation.control == "passed" and observation.body_sha256 != request["body_sha256"]:
            raise RunnerFailure(
                "invalid_control_observation", "Driver response disagrees with expected control"
            )
        if observation.validation is not None and not authorize_validation:
            raise RunnerFailure(
                "unexpected_validation", "Control attempt returned validation evidence"
            )
        driver = observation
        execution = "completed" if driver.control != "not_run" else "failed"
        if driver.control != "passed":
            reasons.append(
                Reason(
                    code=driver.reason,
                    message="Application startup or legitimate control did not pass",
                )
            )
    except KeyboardInterrupt:
        interrupted = True
        execution = "interrupted"
        reasons.append(Reason(code="interrupted", message="Control interrupted; cleanup attempted"))
    except RunnerFailure as exc:
        if exc.code == "command_timeout":
            execution = "timed_out"
        elif exc.code == "output_limit":
            execution = "output_limit"
        reasons.append(Reason(code=exc.code, message=str(exc)))
    except ValueError, OSError, KeyError, TypeError, AttributeError:
        reasons.append(
            Reason(
                code="invalid_runtime_observation",
                message="Docker or driver response is unreadable or inconsistent",
            )
        )
    finally:
        if creation_attempted and client is not None:
            cleanup = "verified_absent" if cleanup_container(client, name) else "unverified"
            if cleanup == "unverified":
                reasons.append(
                    Reason(
                        code="cleanup_unverified",
                        message="Container absence unverified; retain reservation for recovery",
                    )
                )
        report = RepositoryControlAttempt(
            schema_version="1.2",
            validator_id=entry["template_id"] if authorize_validation else None,
            context=ExecutionContext(
                application=ApplicationProfile(
                    source_fingerprint=image.source_fingerprint,
                    entry_point=image.configuration.entry_point,
                    image_id=image.image_id,
                    preparation_sha256=sha(prepared_data),
                ),
                invocation=invocation_from_request(
                    {**request, "query_key": entry["query_key"]}, entry.get("http_request")
                ),
            ),
            http_request=entry.get("http_request"),
            profile="repository-validation-attempt-v1"
            if authorize_validation
            else "repository-control-v1",
            authorization_scope="repository_cwe22_validation"
            if authorize_validation
            else "repository_control_only",
            container_name=name,
            image_id=image.image_id,
            source_fingerprint=image.source_fingerprint,
            plan_sha256=sha(plan_data),
            preparation_sha256=sha(prepared_data),
            driver_sha256=image.driver_sha256,
            finding_id=finding_id,
            candidate_result_id=candidate,
            path_ids=tuple(entry["candidates"][candidate]),
            supporting_path_ids=tuple(dict.fromkeys(s["path_id"] for s in entry["support"])),
            scanner_source_state=rebuilt["scanner_source_state"],
            request=request,
            requested=planning_catalog().execution,
            policy_verified=policy_verified,
            execution=execution,
            cleanup=cleanup,
            container_exit_code=exit_code,
            oom_killed=oom,
            driver=driver,
            commands=tuple(client.commands) if client else (),
            reasons=tuple(reasons),
        )
        publish(destination / "attempt.json", report.model_dump_json(indent=2) + "\n")
    if interrupted:
        raise KeyboardInterrupt
    return report
