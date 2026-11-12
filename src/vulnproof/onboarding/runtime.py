"""Execute a verified application plan with a separate observer and owned cleanup."""

import hashlib
import json
import re
import signal
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from vulnproof.models.common import Contract, Sha256
from vulnproof.runner.docker import DockerClient, RunnerFailure
from vulnproof.runner.engine import cleanup_container, cleanup_signals, inspection, publish
from vulnproof.runner.models import DockerCommand
from vulnproof.runner.profile import DAEMON_FORMAT, create_args, verify_container, verify_daemon
from vulnproof.runner.repository import BASE

from .models import ObserverResult, OnboardingPlan, PreparedApplication
from .planning import read, verify_plan
from .preparation import recipes, worker_bytes


class ApplicationAttempt(Contract):
    schema_version: Literal["1.0"] = "1.0"
    profile: Literal["application-exercise-v1"] = "application-exercise-v1"
    onboarding: OnboardingPlan
    prepared: PreparedApplication
    plan_sha256: Sha256
    preparation_sha256: Sha256
    source_fingerprint: Sha256
    evidence_level: Literal["application", "harness"]
    outcome: Literal["completed", "failed", "interrupted"]
    reason: str
    policy_verified: bool
    execution_policy: Literal["application-internal-isolated-v1"] = (
        "application-internal-isolated-v1"
    )
    test_service_nonce: str
    network: str
    containers: tuple[str, ...]
    observation: dict[str, Any] | None
    application_status: dict[str, Any] | None
    cleanup: dict[str, bool]
    commands: tuple[DockerCommand, ...]
    vulnerability_assessment: None = None


def verify_network(value: dict[str, Any], name: str) -> None:
    if (
        value.get("Name") != name
        or value.get("Driver") != "bridge"
        or value.get("Internal") is not True
        or value.get("EnableIPv6") is not False
        or value.get("Labels", {}).get("vulnproof.onboarding") != name
        or value.get("Options", {}).get("com.docker.network.bridge.gateway_mode_ipv4") != "isolated"
    ):
        raise RunnerFailure(
            "network_policy_mismatch",
            "An isolated internal bridge is required; no fallback is allowed",
        )


def verify_application_image(value: dict[str, Any], image: str, workdir: str) -> None:
    config = value.get("Config", {})
    if (
        value.get("Id") != image
        or value.get("Os") != "linux"
        or config.get("User") != "10001:10001"
        or config.get("WorkingDir") != workdir
        or config.get("Entrypoint")
        or config.get("Volumes")
        or config.get("OnBuild")
        or config.get("Healthcheck", {}).get("Test") != ["NONE"]
        or config.get("Cmd")
        != ["python", "-I", "-c", "raise SystemExit('Use an authorized application runner')"]
    ):
        raise RunnerFailure(
            "image_policy_mismatch", "Prepared image does not satisfy its fixed recipe"
        )


def cleanup_network(client: DockerClient, name: str) -> bool:
    try:
        value = inspection(
            client.run(["network", "inspect", name], "cleanup-network-owner", cleanup=True)
        )
        if value.get("Labels", {}).get("vulnproof.onboarding") == name and not value.get(
            "Containers"
        ):
            client.run(
                ["network", "rm", name], "cleanup-network-remove", cleanup=True, expected=(0, 1)
            )
    except RunnerFailure, ValueError, OSError:
        pass
    try:
        names = client.run(
            ["network", "ls", "--filter", "name=" + name, "--format={{.Name}}"],
            "cleanup-network-absence",
            cleanup=True,
        )
        return name not in names.decode().splitlines()
    except RunnerFailure, ValueError, OSError:
        return False


def exercise_application(
    *,
    scan: Path,
    plan: Path,
    config: Path,
    preparation: Path,
    socket: Path,
    output: Path,
    authorize_execution: bool,
) -> ApplicationAttempt:
    if not authorize_execution:
        raise RunnerFailure("authorization_required", "Authorize application execution explicitly")
    scan, plan, config, preparation, output = (
        p.absolute() for p in (scan, plan, config, preparation, output)
    )
    try:
        raw, selected = verify_plan(scan, plan, config)
        receipt_bytes = read(preparation, 4 * 1024 * 1024)
        receipt = PreparedApplication.model_validate_json(receipt_bytes)
    except (ValueError, OSError) as exc:
        raise RunnerFailure(
            "invalid_execution_input", "Expected consistent onboarding and preparation evidence"
        ) from exc
    app = selected.application
    if (
        app is None
        or receipt.application != app
        or receipt.plan_sha256 != hashlib.sha256(raw).hexdigest()
        or receipt.scan_sha256 != selected.scan_sha256
        or receipt.source_fingerprint != selected.source_fingerprint
        or receipt.base_image != BASE
        or receipt.worker_sha256 != hashlib.sha256(worker_bytes()).hexdigest()
        or receipt.recipe_sha256
        != hashlib.sha256(b"".join(recipes(app.image_directories))).hexdigest()
    ):
        raise RunnerFailure(
            "preparation_mismatch",
            "Preparation differs from installed worker, source or onboarding plan; rebuild",
        )
    if any(
        a.resolve().is_relative_to(b.resolve())
        for source in (scan, plan, config, preparation.parent)
        for a, b in ((output, source), (source, output))
    ):
        raise RunnerFailure(
            "invalid_output", "Choose a new execution directory separate from retained inputs"
        )
    output.mkdir(mode=0o700)
    (output / "diagnostics").mkdir()
    network = "vulnproof-app-" + uuid4().hex
    app_name, observer_name = network + "-target", network + "-observer"
    nonce = uuid4().hex
    names = [app_name] + ([observer_name] if app.kind == "http" else [])
    publish(
        output / "reservation.json",
        json.dumps(
            {
                "network": network,
                "containers": names,
                "plan_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
        + "\n",
    )
    client = DockerClient(socket, output)
    created: list[str] = []
    network_attempted = False
    policy = False
    observation = status = None
    reason = "execution_failed"
    outcome: Literal["completed", "failed", "interrupted"] = "failed"
    clean: dict[str, bool] = {}
    interrupted = False
    target_payload = app.model_dump_json(
        exclude={"controls", "readiness", "wheels", "image_directories"}
    )
    observer_payload = app.model_dump_json(include={"port", "readiness", "controls"})
    previous: dict[signal.Signals, Any] = {}

    def terminate(signum: int, frame: object) -> None:
        raise KeyboardInterrupt

    try:
        for sig in (signal.SIGTERM,):
            previous[sig] = signal.signal(sig, terminate)
        verify_daemon(json.loads(client.run(["info", DAEMON_FORMAT], "daemon")))
        verify_application_image(
            inspection(client.run(["image", "inspect", receipt.app_image], "application-image")),
            receipt.app_image,
            "/application",
        )
        verify_application_image(
            inspection(client.run(["image", "inspect", receipt.observer_image], "observer-image")),
            receipt.observer_image,
            "/opt/vulnproof",
        )
        network_attempted = True
        client.run(
            [
                "network",
                "create",
                "--driver=bridge",
                "--internal",
                "--opt=com.docker.network.bridge.gateway_mode_ipv4=isolated",
                "--label=vulnproof.onboarding=" + network,
                network,
            ],
            "network-create",
        )
        verify_network(
            inspection(client.run(["network", "inspect", network], "network-inspect")), network
        )
        commands = {
            app_name: ["-I", "/opt/vulnproof/worker.py", "application", target_payload],
            observer_name: [
                "-I",
                "/opt/vulnproof/worker.py",
                "observer",
                observer_payload,
                app_name,
                nonce,
            ],
        }
        for name in names:
            image = receipt.app_image if name == app_name else receipt.observer_image
            workdir = (
                "/application" + ("/" + app.workdir if app.workdir else "")
                if name == app_name
                else "/opt/vulnproof"
            )
            args = create_args(name, image, command=commands[name], workdir=workdir)
            args[args.index("--network=none")] = "--network=" + network
            created.append(name)  # Reserve cleanup before attempting creation.
            client.run(args, "create")
            verify_container(
                inspection(client.run(["inspect", name], "inspect")),
                image,
                name,
                command=commands[name],
                workdir=workdir,
                network=network,
            )
        policy = True
        if app.kind == "http":
            client.run(["start", app_name], "start-application")
            data = client.run(["start", "--attach", observer_name], "start", timeout=50)
            observation = ObserverResult.model_validate_json(data).model_dump(mode="json")
            if not isinstance(observation, dict) or set(observation) != {
                "outcome",
                "reason",
                "ready",
                "controls",
                "callbacks",
                "egress_probe_connected",
                "runtime_checks",
            }:
                raise ValueError("Invalid observer document")
            observer_state = inspection(client.run(["inspect", observer_name], "observer-state"))[
                "State"
            ]
            if observer_state["ExitCode"] != 0 or observer_state.get("OOMKilled"):
                raise RunnerFailure("observer_failed", "Observer did not exit successfully")
            controls = observation["controls"]
            complete_controls = (
                isinstance(controls, list)
                and len(controls) == len(app.controls)
                and all(
                    isinstance(item, dict)
                    and item.get("matched") is True
                    and item.get("method") == expected.method
                    and re.fullmatch(
                        re.escape(expected.target).replace(
                            re.escape("${TEST_SERVICE_URL}"),
                            r"http://[0-9.]+:9001/callback/" + nonce,
                        ),
                        str(item.get("target")),
                    )
                    is not None
                    and item.get("status") == expected.expected_status
                    and item.get("body_sha256") == expected.expected_body_sha256
                    and item.get("truncated") is False
                    for item, expected in zip(controls, app.controls, strict=True)
                )
            )
            outcome = (
                "completed"
                if observation["outcome"] == "completed"
                and observation["egress_probe_connected"] is False
                and observation["ready"] is True
                and set(observation["runtime_checks"])
                == {
                    "non_root",
                    "zero_capabilities",
                    "no_new_privileges",
                    "readonly_root",
                    "temporary_write",
                    "no_default_ipv4_route",
                }
                and all(v is True for v in observation["runtime_checks"].values())
                and complete_controls
                and all(c["path"] == "/callback/" + nonce for c in observation["callbacks"])
                else "failed"
            )
            reason = (
                "observer_evidence_mismatch"
                if outcome == "failed" and observation["outcome"] == "completed"
                else str(observation["reason"])
            )
        else:
            data = client.run(["start", "--attach", app_name], "start", timeout=60, expected=(0, 1))
            status = json.loads(data)
            state = inspection(client.run(["inspect", app_name], "harness-state"))["State"]
            outcome = (
                "completed"
                if state["ExitCode"] == 0
                and not state.get("OOMKilled")
                and status.get("outcome") == "completed"
                and status.get("exit_code") == 0
                else "failed"
            )
            reason = "harness_completed" if outcome == "completed" else "harness_failed"
        if app.kind == "http":
            status = json.loads(
                client.run(
                    ["exec", app_name, "python", "-I", "/opt/vulnproof/worker.py", "status", "{}"],
                    "application-status",
                )
            )
        if app.kind == "http":
            state = inspection(client.run(["inspect", app_name], "application-state"))["State"]
            if status is not None:
                status["container_state"] = {
                    k: state.get(k) for k in ("Running", "ExitCode", "OOMKilled")
                }
            if state.get("OOMKilled") or not state.get("Running"):
                outcome, reason = "failed", "application_container_stopped"
        if status and status.get("outcome") in ("failed", "output_limit", "timed_out"):
            outcome, reason = (
                "failed",
                ("initialization_" if status.get("stage") == "initialize" else "application_")
                + str(status["outcome"]),
            )
    except KeyboardInterrupt:
        interrupted = True
        outcome, reason = "interrupted", "interrupted"
    except (RunnerFailure, OSError, ValueError, KeyError, TypeError) as exc:
        outcome, reason = "failed", getattr(exc, "code", "invalid_runtime_observation")
    finally:
        with cleanup_signals():
            for name in reversed(created):
                clean[name] = cleanup_container(client, name)
            if network_attempted:
                clean[network] = cleanup_network(client, network)
            if not all(clean.values()):
                outcome, reason = "failed", "cleanup_unverified"
            result = ApplicationAttempt(
                onboarding=selected,
                prepared=receipt,
                plan_sha256=hashlib.sha256(raw).hexdigest(),
                preparation_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
                source_fingerprint=selected.source_fingerprint,
                evidence_level="application" if app.kind == "http" else "harness",
                outcome=outcome,
                reason=reason,
                policy_verified=policy,
                test_service_nonce=nonce,
                network=network,
                containers=tuple(names),
                observation=observation,
                application_status=status,
                cleanup=clean,
                commands=tuple(client.commands),
            )
        try:
            publish(output / "result.json", result.model_dump_json(indent=2) + "\n")
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    if interrupted:
        raise KeyboardInterrupt
    return result
