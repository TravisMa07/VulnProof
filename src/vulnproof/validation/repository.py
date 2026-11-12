"""Classify one repository occurrence using retained plans and bounded runtime observations."""

import json
from pathlib import Path
from typing import Any, Literal

from vulnproof.investigation.assessment import ValidationEvidence, assess
from vulnproof.investigation.contracts import Classification, invocation_from_request
from vulnproof.models.common import Contract, Sha256
from vulnproof.planning.repository import plan_repository, unique_fields
from vulnproof.runner.controls import RepositoryControlAttempt, check_repository, read
from vulnproof.runner.docker import RunnerFailure
from vulnproof.runner.engine import publish
from vulnproof.runner.repository import sha

from .registry import VALIDATORS


class RepositoryValidation(Contract):
    schema_version: Literal["1.0"] = "1.0"
    profile: Literal["repository-validation-v1"] = "repository-validation-v1"
    finding_id: str
    source_fingerprint: Sha256
    plan_sha256: Sha256
    classification: Classification
    reason: str
    finding: dict[str, Any]
    scanner_source_state: Literal["controlled_snapshot", "unverified"]
    attempt: RepositoryControlAttempt | None


def classify(
    attempt: RepositoryControlAttempt, validator_id: str | None = None
) -> tuple[Classification, str]:
    if (
        validator_id is not None
        and attempt.validator_id is not None
        and validator_id != attempt.validator_id
    ):
        return "failed", "validator_identity_mismatch"
    selected_validator = validator_id or attempt.validator_id or "cwe22-file-read-v1"
    invocation_request = {
        **attempt.request,
        "query_key": attempt.request.get("query_key", "unresolved"),
    }
    try:
        invocation = invocation_from_request(invocation_request, attempt.http_request)
        evidence = ValidationEvidence(
            execution=attempt.execution,
            policy_verified=attempt.policy_verified,
            cleanup=attempt.cleanup,
            control_valid=bool(attempt.driver and attempt.driver.control == "passed"),
            scanner_source_state=attempt.scanner_source_state,
            invocation=invocation,
            observations=attempt.driver.validation if attempt.driver else None,
            operational_reason=attempt.driver.reason if attempt.driver else None,
        )
        decision = assess(selected_validator, evidence, VALIDATORS)
        return decision.classification, decision.reason
    except ValueError, KeyError, TypeError:
        return "failed", "invalid_validation_observation"


def validate_repository(
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
    authorize_validation: bool,
) -> RepositoryValidation:
    if not authorize_validation:
        raise RunnerFailure(
            "authorization_required", "Explicit repository validation authorization is required"
        )
    try:
        original = read(plan)
        document = json.loads(plan_repository(scan, investigation, correlation, discovery, config))
        if json.loads(original, object_pairs_hook=unique_fields) != document:
            raise RunnerFailure("plan_mismatch", "Plan differs from retained evidence")
        rows = [r for r in document["findings"] if r["finding_id"] == finding_id]
        if len(rows) != 1:
            raise RunnerFailure("unknown_finding", "Select one occurrence from the verified plan")
        row = rows[0]
        destination = output.absolute()
        inputs = [scan, investigation, correlation, discovery, plan, preparation.parent]
        if config:
            inputs.append(config)
        if any(
            a.resolve().is_relative_to(b.resolve())
            for p in inputs
            for a, b in ((destination, p), (p, destination))
        ):
            raise RunnerFailure(
                "invalid_output", "Choose a new directory separate from retained inputs"
            )
        destination.mkdir(mode=0o700)
    except RunnerFailure:
        raise
    except (ValueError, OSError, KeyError, TypeError) as exc:
        raise RunnerFailure(
            "invalid_validation_input", "Invalid retained evidence or output"
        ) from exc
    attempt = None
    classification: Classification = "inconclusive"
    reason = "planning_prerequisites_missing"
    interrupted = False
    try:
        if row["status"] == "draft" and row.get("template_id") not in VALIDATORS:
            classification, reason = "unsupported", "unsupported_validator"
        elif row["status"] == "draft":
            attempt = check_repository(
                scan=scan,
                investigation=investigation,
                correlation=correlation,
                discovery=discovery,
                plan=plan,
                config=config,
                preparation=preparation,
                finding_id=finding_id,
                socket=socket,
                output=destination / "runtime",
                authorize_execution=False,
                authorize_validation=True,
            )
            classification, reason = classify(attempt, row["template_id"])
        elif row["correlation_status"] == "unsupported_mapping" or "unsupported_method" in row.get(
            "reasons", []
        ):
            classification, reason = "unsupported", "unsupported_mapping"
        elif document["analysis_outcome"] == "failed":
            classification, reason = "failed", "analysis_failed"
    except KeyboardInterrupt:
        interrupted = True
        classification, reason = "failed", "interrupted"
        retained = destination / "runtime/attempt.json"
        if retained.exists():
            attempt = RepositoryControlAttempt.model_validate_json(read(retained))
    except (RunnerFailure, ValueError, OSError) as exc:
        classification, reason = "failed", getattr(exc, "code", "validation_failed")
    result = RepositoryValidation(
        finding_id=finding_id,
        source_fingerprint=document["source_fingerprint"],
        plan_sha256=sha(original),
        classification=classification,
        reason=reason,
        finding=row,
        scanner_source_state=document["scanner_source_state"],
        attempt=attempt,
    )
    publish(destination / "plan.json", original.decode())
    publish(destination / "result.json", result.model_dump_json(indent=2) + "\n")
    if interrupted:
        raise KeyboardInterrupt
    return result
