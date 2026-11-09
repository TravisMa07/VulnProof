"""Use the existing runner policy and lifecycle primitives for approved probes."""

import hashlib
import json
from pathlib import Path
from typing import Literal
from uuid import uuid4

from vulnproof.models import Reason
from vulnproof.runner.docker import DockerClient, RunnerFailure
from vulnproof.runner.engine import cleanup_container, inspection, publish
from vulnproof.runner.models import PreparedImage
from vulnproof.runner.profile import (
    DAEMON_FORMAT,
    create_args,
    verify_container,
    verify_daemon,
    verify_image,
)

from .models import PROFILE, Attempt, Driver, Preparation
from .preparation import select_image


def execute(
    *,
    image: PreparedImage,
    prepared: Preparation,
    preparation_data: bytes,
    plan_data: bytes,
    finding_id: str,
    candidate_id: str,
    path_id: str,
    socket: Path,
    output: Path,
    authorize_validation: bool,
) -> Attempt:
    if not authorize_validation:
        raise RunnerFailure(
            "authorization_required", "Explicit CWE-22 validation authorization required"
        )
    if (
        Preparation.model_validate_json(preparation_data) != prepared
        or select_image(prepared, image.fixture_id, image.source_fingerprint) != image
    ):
        raise RunnerFailure(
            "image_source_mismatch", "Runtime image is not the approved prepared image"
        )
    # Caller additionally verifies the selected finding and retained plan.
    name = "vulnproof-validation-" + uuid4().hex
    publish(
        output / "reservation.json",
        json.dumps({"container_name": name, "image_id": image.image_id}) + "\n",
    )
    client = None
    creation_attempted = policy_verified = interrupted = False
    execution: Literal[
        "not_started", "completed", "failed", "timed_out", "output_limit", "interrupted"
    ] = "not_started"
    cleanup: Literal["not_needed", "verified_absent", "unverified"] = "not_needed"
    driver = None
    exit_code = oom = None
    reasons: list[Reason] = []
    try:
        client = DockerClient(socket, output)
        verify_daemon(json.loads(client.run(["info", DAEMON_FORMAT], "daemon")))
        verify_image(
            inspection(client.run(["image", "inspect", image.image_id], "image-inspect")),
            image.image_id,
        )
        creation_attempted = True
        client.run(create_args(name, image.image_id), "create", timeout=30)
        verify_container(
            inspection(client.run(["inspect", name], "container-inspect")), image.image_id, name
        )
        policy_verified = True
        execution = "failed"
        data = client.run(["start", "--attach", name], "start", timeout=60)
        # Parse first to preserve any disclosure if the subsequent state check fails.
        driver = Driver.model_validate_json(data)
        state = inspection(client.run(["inspect", name], "state"))["State"]
        if (
            state["Running"] is not False
            or type(state["ExitCode"]) is not int
            or type(state["OOMKilled"]) is not bool
        ):
            raise RunnerFailure(
                "invalid_container_state", "Validation container has no valid final state"
            )
        exit_code, oom = state["ExitCode"], state["OOMKilled"]
        if exit_code != 0 or oom or driver.outcome != "completed":
            raise RunnerFailure("validation_failed", "Driver or container did not complete")
        execution = "completed"
    except KeyboardInterrupt:
        interrupted = True
        execution = "interrupted"
        reasons.append(
            Reason(code="interrupted", message="Validation interrupted; cleanup attempted")
        )
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
                message="Docker or validation response is inconsistent",
            )
        )
    finally:
        if creation_attempted and client is not None:
            cleanup = "verified_absent" if cleanup_container(client, name) else "unverified"
            if cleanup == "unverified":
                reasons.append(
                    Reason(
                        code="cleanup_unverified",
                        message="Container absence not verified; retain reservation for recovery",
                    )
                )
        report = Attempt(
            schema_version="1.0",
            profile=PROFILE,
            attempt_id=name,
            fixture_id=image.fixture_id,
            image=image,
            preparation_sha256=hashlib.sha256(preparation_data).hexdigest(),
            approval_sha256=prepared.approval_sha256,
            plan_sha256=hashlib.sha256(plan_data).hexdigest(),
            finding_id=finding_id,
            candidate_result_id=candidate_id,
            path_id=path_id,
            execution_authorized=True,
            authorization_scope="fixture_cwe22_validation_only",
            policy_verified=policy_verified,
            execution=execution,
            cleanup=cleanup,
            exit_code=exit_code,
            oom_killed=oom,
            driver=driver,
            commands=tuple(client.commands) if client else (),
            reasons=tuple(reasons),
        )
        publish(output / "attempt.json", report.model_dump_json(indent=2) + "\n")
    if interrupted:
        raise KeyboardInterrupt
    return report
