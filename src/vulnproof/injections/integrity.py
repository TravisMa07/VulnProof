"""Recheck inspected policy and exact installed observer invocation from retained logs."""

import json
from collections import defaultdict
from pathlib import Path

from vulnproof.correlation.engine import _artifact
from vulnproof.onboarding.models import ObserverResult
from vulnproof.onboarding.runtime import (
    ApplicationAttempt,
    verify_application_image,
    verify_network,
)
from vulnproof.runner.profile import verify_container
from vulnproof.static.models import MAX_LOG_BYTES


def verify_attempt(directory: Path, attempt: ApplicationAttempt) -> None:
    logs: dict[str, list[bytes]] = defaultdict(list)
    for command in attempt.commands:
        raw = _artifact(directory, command.log, MAX_LOG_BYTES)
        if command.outcome == "completed" and not command.log.truncated:
            logs[command.stage].append(raw)
    if attempt.outcome != "completed":
        return  # Failure diagnostics may be incomplete; they cannot support confirmation.
    app = attempt.prepared.application
    validation = attempt.validation_request
    if validation is None or app.kind != "http" or not attempt.policy_verified:
        raise ValueError("Missing application-level validation identity")
    names = (attempt.network + "-target", attempt.network + "-observer")
    if (
        attempt.containers != names
        or set(attempt.cleanup) != {*names, attempt.network}
        or not all(attempt.cleanup.values())
    ):
        raise ValueError("Incomplete owned-resource cleanup identity")
    if len(logs["network-inspect"]) != 1 or len(logs["inspect"]) != 2:
        raise ValueError("Missing policy inspections")
    verify_network(json.loads(logs["network-inspect"][0])[0], attempt.network)
    target = app.model_dump(
        mode="json", exclude={"controls", "readiness", "wheels", "image_directories"}
    )
    target["validation_nonce"] = attempt.test_service_nonce
    observer = app.model_dump(mode="json", include={"port", "readiness", "controls"})
    observer["validation"] = validation.model_dump(mode="json")
    payloads = (json.dumps(target), json.dumps(observer))
    commands = (
        ["-I", "/opt/vulnproof/worker.py", "application", payloads[0]],
        [
            "-I",
            "/opt/vulnproof/worker.py",
            "observer",
            payloads[1],
            names[0],
            attempt.test_service_nonce,
        ],
    )
    # JSON object spacing is immaterial; argv, selected worker and payload values are checked.
    for index, raw in enumerate(logs["inspect"]):
        value = json.loads(raw)[0]
        observed_command = value["Config"]["Cmd"]
        expected = commands[index]
        if len(observed_command) != len(expected) or json.loads(observed_command[3]) != json.loads(
            expected[3]
        ):
            raise ValueError("Installed observer/application payload differs")
        expected[3] = observed_command[3]
        verify_container(
            value,
            attempt.prepared.app_image if index == 0 else attempt.prepared.observer_image,
            names[index],
            command=expected,
            workdir=("/application" + ("/" + app.workdir if app.workdir else ""))
            if index == 0
            else "/opt/vulnproof",
            network=attempt.network,
        )
    for stage, image, workdir in (
        ("application-image", attempt.prepared.app_image, "/application"),
        ("observer-image", attempt.prepared.observer_image, "/opt/vulnproof"),
    ):
        if len(logs[stage]) != 1:
            raise ValueError("Missing immutable-image inspection")
        verify_application_image(json.loads(logs[stage][0])[0], image, workdir)
    if (
        len(logs["start"]) != 1
        or ObserverResult.model_validate_json(logs["start"][0]).model_dump(mode="json")
        != attempt.observation
    ):
        raise ValueError("Observer evidence differs from retained Docker transcript")
    for stage in ("observer-state", "application-state"):
        if len(logs[stage]) != 1:
            raise ValueError("Missing execution state")
        state = json.loads(logs[stage][0])[0]["State"]
        if (
            state.get("OOMKilled")
            or (stage == "observer-state" and state["ExitCode"] != 0)
            or (stage == "application-state" and not state["Running"])
        ):
            raise ValueError("Unsuccessful application/observer state")
    if len(logs["cleanup-absence"]) != 2 or any(raw.strip() for raw in logs["cleanup-absence"]):
        raise ValueError("Container absence is not independently verified")
    if (
        len(logs["cleanup-network-absence"]) != 1
        or attempt.network in logs["cleanup-network-absence"][0].decode().splitlines()
    ):
        raise ValueError("Network absence is not independently verified")
