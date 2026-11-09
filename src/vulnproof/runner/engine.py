"""One explicitly authorized fixture diagnostic attempt; no vulnerability probes."""

import hashlib
import json
import os
import signal
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal, cast
from uuid import uuid4

from vulnproof.artifacts import read_local
from vulnproof.correlation.engine import MAX_DOCUMENT_BYTES
from vulnproof.models import Reason
from vulnproof.planning import PlanningDocument, PlanningFailure, create_plans
from vulnproof.static.analysis import fixture_manifest

from .docker import DockerClient, RunnerFailure
from .models import DriverReport, PreparationRecord, PreparedImage, RunnerAttempt
from .profile import (
    DAEMON_FORMAT,
    approval_bytes,
    create_args,
    recipe_hash,
    runner_approval,
    verify_container,
    verify_daemon,
    verify_image,
)


def publish(path: Path, content: str) -> None:
    """Private directory, exclusive complete-file publication."""
    temporary = path.with_name("." + path.name + ".pending")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def selected_image(
    record: PreparationRecord, fixture_id: str, fingerprint: str | None
) -> PreparedImage:
    if record.approval_sha256 != hashlib.sha256(approval_bytes()).hexdigest():
        raise RunnerFailure(
            "stale_preparation", "Preparation does not match installed recipe approval"
        )
    recipes = {r.fixture_id: r for r in runner_approval().recipes}
    known = {f.id: f.fingerprint for f in fixture_manifest().fixtures}
    for image in record.images:
        recipe = recipes.get(image.fixture_id)
        if (
            recipe is None
            or image.source_fingerprint != known.get(image.fixture_id)
            or image.recipe_sha256 != recipe_hash(recipe)
        ):
            raise RunnerFailure(
                "invalid_preparation", "Prepared images disagree with installed approvals"
            )
    selected = next((i for i in record.images if i.fixture_id == fixture_id), None)
    if selected is None or selected.source_fingerprint != fingerprint:
        raise RunnerFailure(
            "image_source_mismatch", "No compatible prepared image for the selected capture"
        )
    return selected


def inspection(data: bytes) -> dict[str, Any]:
    value = json.loads(data)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ValueError("expected one inspected object")
    return cast(dict[str, Any], value[0])


@contextmanager
def cleanup_signals() -> Iterator[None]:
    """Let one interruption unwind cleanup; repeated termination cannot abort it."""
    previous: dict[signal.Signals, Any] = {}
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, signal.SIG_IGN)
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def cleanup_container(client: DockerClient, name: str) -> bool:
    with cleanup_signals():
        try:
            labels = json.loads(
                client.run(
                    ["inspect", "--format={{json .Config.Labels}}", name],
                    "cleanup-owner",
                    cleanup=True,
                )
            )
            if isinstance(labels, dict) and labels.get("vulnproof.attempt") == name:
                client.run(
                    ["rm", "--force", name],
                    "cleanup-remove",
                    timeout=20,
                    cleanup=True,
                    expected=(0, 1),
                )
        except RunnerFailure, ValueError, OSError:
            # Removal may fail after the daemon accepted it; verify absence independently.
            pass
        try:
            absent = client.run(
                ["ps", "--all", "--quiet", "--filter", f"name=^/{name}$"],
                "cleanup-absence",
                cleanup=True,
            )
            return not absent.strip()
        except RunnerFailure, ValueError, OSError:
            return False


def run_diagnostics(
    *,
    capture: Path,
    analysis: Path,
    correlation: Path,
    plan: Path,
    preparation: Path,
    finding_id: str,
    socket: Path,
    output: Path,
    authorize_execution: bool,
) -> RunnerAttempt:
    if not authorize_execution:
        raise RunnerFailure(
            "authorization_required", "Explicit authorization is required for fixture diagnostics"
        )
    try:
        plan_data = read_local(plan.absolute().parent, plan.name, MAX_DOCUMENT_BYTES)
        document = PlanningDocument.model_validate_json(plan_data)
        if document != create_plans(capture, analysis, correlation):
            raise RunnerFailure(
                "plan_mismatch",
                "Plan does not reproduce from retained evidence and installed catalog",
            )
        entry = next((e for e in document.findings if e.finding_id == finding_id), None)
        if entry is None or entry.plan is None or entry.disposition != "draft":
            raise RunnerFailure(
                "finding_not_eligible", "Select exactly one draft finding from the verified plan"
            )
        prepared_data = read_local(
            preparation.absolute().parent, preparation.name, MAX_DOCUMENT_BYTES
        )
        prepared = PreparationRecord.model_validate_json(prepared_data)
        image = selected_image(
            prepared, document.fixture.fixture_id, document.correlation.snapshot.fingerprint
        )
        destination = output.absolute()
        if any(
            destination.parent.resolve().joinpath(destination.name).is_relative_to(p.resolve())
            for p in (capture, analysis)
        ) or destination.resolve() in (
            plan.resolve(),
            preparation.resolve(),
            correlation.resolve(),
        ):
            raise RunnerFailure(
                "invalid_output", "Attempt directory must be new and outside input evidence"
            )
        destination.mkdir(mode=0o700)
        (destination / "diagnostics").mkdir(mode=0o700)
    except RunnerFailure:
        raise
    except (ValueError, OSError, PlanningFailure) as exc:
        raise RunnerFailure(
            "invalid_runner_input",
            "Evidence or preparation is unreadable, changed, or inconsistent; output must be new",
        ) from exc
    name = "vulnproof-runner-" + uuid4().hex
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
    exit_code: int | None = None
    oom: bool | None = None
    driver: DriverReport | None = None
    reasons: list[Reason] = []
    try:
        client = DockerClient(socket, destination)
        try:
            daemon_info = client.run(["info", DAEMON_FORMAT], "daemon")
        except RunnerFailure as exc:
            raise RunnerFailure(
                "daemon_unavailable",
                "Local Docker daemon unavailable; start Docker Desktop/Engine and check the selected socket; see diagnostics",
            ) from exc
        verify_daemon(json.loads(daemon_info))
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
                "container_failed", "Container exit/OOM state failed diagnostic acceptance"
            )
        driver = DriverReport.model_validate_json(data)
        execution = "completed"
    except KeyboardInterrupt:
        interrupted = True
        execution = "interrupted"
        reasons.append(
            Reason(
                code="interrupted", message="Diagnostic operation interrupted; cleanup attempted"
            )
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
                        message="Container absence could not be verified; retain its name for recovery",
                    )
                )
        report = RunnerAttempt(
            schema_version="1.0",
            profile="fixture-diagnostics-v1",
            attempt_id=name,
            container_name=name,
            fixture_id=image.fixture_id,
            image_id=image.image_id,
            source_fingerprint=image.source_fingerprint,
            plan_sha256=hashlib.sha256(plan_data).hexdigest(),
            preparation_sha256=hashlib.sha256(prepared_data).hexdigest(),
            approval_sha256=prepared.approval_sha256,
            finding_id=finding_id,
            candidate_result_id=entry.plan.candidate_result_id,
            path_ids=entry.plan.path_ids,
            execution_authorized=True,
            requested=document.execution_requirements,
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
