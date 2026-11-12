"""Independent host checks of bounded observer evidence; failed probes never prove safety."""

import hashlib
import json
import re
from typing import Any

from vulnproof.investigation.assessment import ValidationEvidence
from vulnproof.investigation.contracts import Decision, GetRequest
from vulnproof.onboarding.worker import injection_probes, injection_target

from .models import Capability, ValidationObservation


def assess_injection(capability: Capability, evidence: ValidationEvidence) -> Decision:
    observation = evidence.observations
    if not observation or not isinstance(observation.get("validation"), dict):
        return Decision(classification="failed", reason="validation_observation_missing")
    result = ValidationObservation.model_validate_json(
        json.dumps(observation["validation"])
    ).model_dump(mode="json")
    nonce = result.get("nonce")
    if (
        result.get("capability") != capability
        or not isinstance(nonce, str)
        or not re.fullmatch(r"[a-f0-9]{32}", nonce)
    ):
        raise ValueError("Wrong validator identity or nonce")
    if not result.get("control_valid") or evidence.invocation.request_profile is None:
        return Decision(classification="failed", reason="validation_control_failed")
    request = evidence.invocation.request_profile
    marker = "VP_" + nonce
    expected = injection_probes(capability, request.control_value, nonce)
    attempts = result["attempts"]
    control = result["control"]
    verify_request(control, request, request.control_value)
    if (
        control["status"] != 200
        or control["body_sha256"] != evidence.invocation.expected_body_sha256
        or control["marker_present"] is not False
    ):
        raise ValueError("Invalid legitimate control")
    if len(attempts) != len(expected):
        raise ValueError("Incomplete probe sequence")
    found = False
    for observed, probe in zip(attempts, expected, strict=True):
        verify_request(observed, request, probe["value"])
        if observed["role"] != probe["role"] or marker in probe["value"]:
            raise ValueError("Probe identity mismatch")
        if observed["role"] == "negative":
            if (
                observed["status"] != 200
                or observed["marker_present"] is not False
                or observed["body_sha256"] != hashlib.sha256(b"").hexdigest()
            ):
                return Decision(
                    classification="inconclusive", reason="sql_negative_control_unsatisfied"
                )
        elif observed["status"] == 200 and observed["marker_present"] is True:
            found = True
    return Decision(
        classification="confirmed" if found else "inconclusive",
        reason={
            "command": "observed_shell_marker",
            "sql": "observed_synthetic_sql_marker",
            "template": "observed_template_evaluation",
        }[capability]
        if found
        else "bounded_probe_not_confirmed_no_safety_conclusion",
    )


def verify_request(observed: dict[str, Any], profile: GetRequest, value: str) -> None:
    if (
        observed["method"] != "GET"
        or observed["target"] != profile.target(value)
        or observed["target"] != injection_target(profile.model_dump(mode="json"), value)
        or observed["request_body_bytes"] != 0
        or observed["request_body_sha256"] != hashlib.sha256(b"").hexdigest()
        or observed["request_headers_sha256"]
        != hashlib.sha256(json.dumps({}, sort_keys=True).encode()).hexdigest()
        or observed["truncated"] is not False
        or type(observed["marker_present"]) is not bool
        or not isinstance(observed["body_bytes"], int)
        or not 0 <= observed["body_bytes"] <= 65536
        or not re.fullmatch(r"[0-9a-f]{64}", observed["body_sha256"])
    ):
        raise ValueError("Altered request/response evidence")


def command(evidence: ValidationEvidence) -> Decision:
    return assess_injection("command", evidence)


def sql(evidence: ValidationEvidence) -> Decision:
    return assess_injection("sql", evidence)


def template(evidence: ValidationEvidence) -> Decision:
    return assess_injection("template", evidence)
