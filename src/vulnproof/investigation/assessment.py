"""Shared admission gates and explicit validator dispatch, with no tool execution."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .contracts import Decision, HttpInvocation


@dataclass(frozen=True)
class ValidationEvidence:
    execution: str
    policy_verified: bool
    cleanup: str
    control_valid: bool
    scanner_source_state: Literal["controlled_snapshot", "unverified"]
    invocation: HttpInvocation
    observations: dict[str, Any] | None
    operational_reason: str | None = None


Oracle = Callable[[ValidationEvidence], Decision]


def assess(
    validator_id: str, evidence: ValidationEvidence, validators: Mapping[str, Oracle]
) -> Decision:
    oracle = validators.get(validator_id)
    if oracle is None:
        return Decision(classification="unsupported", reason="unsupported_validator")
    if (
        evidence.policy_verified
        and evidence.cleanup == "verified_absent"
        and evidence.operational_reason == "unsupported_application"
    ):
        return Decision(classification="unsupported", reason="unsupported_application")
    if (
        evidence.execution != "completed"
        or not evidence.policy_verified
        or evidence.cleanup != "verified_absent"
        or not evidence.control_valid
    ):
        return Decision(classification="failed", reason="control_execution_or_cleanup_failed")
    observed = evidence.observations
    if not observed or observed.get("outcome") != "completed":
        return Decision(
            classification="failed",
            reason=str(observed.get("reason", "validation_missing"))
            if observed
            else "validation_missing",
        )
    try:
        decision = oracle(evidence)
    except ValueError, KeyError, TypeError, IndexError:
        return Decision(classification="failed", reason="invalid_validation_observation")
    if (
        decision.classification == "confirmed"
        and evidence.scanner_source_state != "controlled_snapshot"
    ):
        return Decision(classification="inconclusive", reason="scanner_source_unverified")
    return decision
