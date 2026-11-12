"""Authorize one source-bound draft and assess the isolated observer's evidence."""

from pathlib import Path
from typing import Literal

from vulnproof.investigation.assessment import ValidationEvidence, assess
from vulnproof.investigation.contracts import Classification, Decision, HttpInvocation
from vulnproof.models.common import Contract, Sha256
from vulnproof.onboarding.planning import read
from vulnproof.onboarding.runtime import ApplicationAttempt, exercise_application
from vulnproof.runner.docker import RunnerFailure
from vulnproof.runner.engine import publish
from vulnproof.validation.registry import VALIDATORS

from .models import Entry, Plans, ValidationRequest
from .planning import LIMIT, digest, plan_injections


class Result(Contract):
    schema_version: Literal["1.0"] = "1.0"
    profile: Literal["injection-validation-v1"] = "injection-validation-v1"
    plans_sha256: Sha256
    finding_id: str
    source_fingerprint: Sha256
    entry: Entry
    scanner_source_state: Literal["controlled_snapshot", "unverified"]
    attempt: ApplicationAttempt | None
    decision: Decision


def decision(
    entry: Entry,
    state: Literal["controlled_snapshot", "unverified"],
    attempt: ApplicationAttempt | None,
) -> Decision:
    if entry.status != "draft" or entry.endpoint is None or entry.capability is None:
        classification: Classification = "unsupported"
        if "analysis_failed" in entry.reasons:
            classification = "failed"
        elif any(
            reason in entry.reasons
            for reason in (
                "compatible_path_missing",
                "ambiguous_sinks",
                "analysis_missing",
                "analysis_partial",
                "scan_incomplete",
            )
        ):
            classification = "inconclusive"
        return Decision(
            classification=classification, reason=";".join(entry.reasons) or "planning_blocked"
        )
    if attempt is None:
        return Decision(classification="failed", reason="execution_missing")
    endpoint = entry.endpoint
    request = ValidationRequest(
        capability=entry.capability,
        request=endpoint.request,
        control_sha256=endpoint.control_sha256,
    )
    if attempt.validation_request != request or attempt.evidence_level != "application":
        return Decision(classification="failed", reason="invocation_identity_mismatch")
    observed = attempt.observation
    if (
        observed
        and observed.get("validation")
        and observed["validation"].get("nonce") != attempt.test_service_nonce
    ):
        return Decision(classification="failed", reason="nonce_identity_mismatch")
    invocation = HttpInvocation(
        request_target=endpoint.request.target(endpoint.request.control_value),
        input_location="query",
        input_name=endpoint.request.query_key,
        expected_body_sha256=endpoint.control_sha256,
        request_profile=endpoint.request,
    )
    return assess(
        f"{entry.capability}-injection-v1",
        ValidationEvidence(
            execution=attempt.outcome,
            policy_verified=attempt.policy_verified,
            cleanup="verified_absent"
            if attempt.cleanup and all(attempt.cleanup.values())
            else "unverified",
            control_valid=bool(
                observed
                and isinstance(observed.get("validation"), dict)
                and observed["validation"].get("control_valid")
            ),
            scanner_source_state=state,
            invocation=invocation,
            observations=observed,
        ),
        VALIDATORS,
    )


def validate_injection(
    *,
    scan: Path,
    investigations: dict[str, Path],
    config: Path | None,
    plan: Path,
    finding_id: str,
    onboarding: Path,
    application_config: Path,
    preparation: Path,
    socket: Path,
    output: Path,
    authorize_validation: bool,
) -> Result:
    if not authorize_validation:
        raise RunnerFailure("authorization_required", "Authorize the bounded validation explicitly")
    raw = read(plan, LIMIT)
    selected = Plans.model_validate_json(raw)
    if selected != plan_injections(scan, investigations, config):
        raise ValueError("Edited injection plan or changed inputs")
    entry = next((e for e in selected.entries if e.finding_id == finding_id), None)
    if entry is None:
        raise ValueError("Unknown SARIF occurrence")
    output = output.absolute()
    if any(
        a.resolve().is_relative_to(b.resolve())
        for source in (
            scan,
            plan,
            onboarding,
            application_config,
            preparation.parent,
            *investigations.values(),
            *((config,) if config else ()),
        )
        for a, b in ((output, source), (source, output))
    ):
        raise ValueError("Choose a new output directory separate from all evidence")
    output.mkdir(mode=0o700)
    attempt = None
    interrupted = False
    if entry.status == "draft" and entry.endpoint and entry.capability:
        endpoint = entry.endpoint
        try:
            attempt = exercise_application(
                scan=scan,
                plan=onboarding,
                config=application_config,
                preparation=preparation,
                socket=socket,
                output=output / "execution",
                authorize_execution=True,
                validation=ValidationRequest(
                    capability=entry.capability,
                    request=endpoint.request,
                    control_sha256=endpoint.control_sha256,
                ),
            )
        except KeyboardInterrupt:
            interrupted = True
            retained = output / "execution/result.json"
            if retained.is_file():
                attempt = ApplicationAttempt.model_validate_json(read(retained, LIMIT))
    result = Result(
        plans_sha256=digest(raw),
        finding_id=finding_id,
        source_fingerprint=selected.source_fingerprint,
        entry=entry,
        scanner_source_state=selected.scanner_source_state,
        attempt=attempt,
        decision=decision(entry, selected.scanner_source_state, attempt),
    )
    publish(output / "result.json", result.model_dump_json(indent=2) + "\n")
    if interrupted:
        raise KeyboardInterrupt
    return result
