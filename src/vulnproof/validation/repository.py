"""Classify one repository occurrence using retained plans and bounded runtime observations."""

import json
import os
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlencode

from vulnproof.models.common import Contract, Sha256
from vulnproof.planning.repository import plan_repository, unique_fields
from vulnproof.runner.controls import RepositoryControlAttempt, check_repository, read
from vulnproof.runner.docker import RunnerFailure
from vulnproof.runner.engine import publish
from vulnproof.runner.repository import sha


class RepositoryValidation(Contract):
    schema_version: Literal["1.0"] = "1.0"
    profile: Literal["repository-validation-v1"] = "repository-validation-v1"
    finding_id: str
    source_fingerprint: Sha256
    plan_sha256: Sha256
    classification: Literal["confirmed", "inconclusive", "unsupported", "failed"]
    reason: str
    finding: dict[str, Any]
    scanner_source_state: Literal["controlled_snapshot", "unverified"]
    attempt: RepositoryControlAttempt | None


def classify(
    attempt: RepositoryControlAttempt,
) -> tuple[Literal["confirmed", "inconclusive", "unsupported", "failed"], str]:
    import re

    if (
        attempt.policy_verified
        and attempt.cleanup == "verified_absent"
        and attempt.driver
        and attempt.driver.reason == "unsupported_application"
    ):
        return "unsupported", "unsupported_application"
    if not attempt.succeeded or not attempt.driver:
        return "failed", "control_execution_or_cleanup_failed"
    observed = attempt.driver.validation
    if not observed or observed.get("outcome") != "completed":
        return "failed", str(
            observed.get("reason", "validation_missing")
        ) if observed else "validation_missing"
    marker, path, root = (observed.get(k) for k in ("canary_body", "canary_path", "download_root"))
    probes = observed.get("probes")
    if (
        observed.get("initially_absent") is not True
        or not isinstance(marker, str)
        or re.fullmatch(r"VulnProof:[0-9a-f]{64}\n", marker) is None
        or not isinstance(path, str)
        or re.fullmatch(r"/tmp/vulnproof/[0-9a-f]{32}\.txt", path) is None
        or not isinstance(root, str)
        or not root.startswith("/")
        or Path(path).is_relative_to(root)
        or not isinstance(probes, list)
        or len(probes) != 2
        or [p.get("kind") for p in probes if isinstance(p, dict)]
        != ["parent_traversal", "absolute_path"]
    ):
        return "failed", "invalid_validation_observation"
    expected_targets = [
        attempt.request["route"] + "?" + urlencode({attempt.request["query_key"]: value})
        for value in (os.path.relpath(path, root), path)
    ]
    if [p.get("request_target") for p in probes] != expected_targets:
        return "failed", "probe_request_mismatch"
    for probe in probes:
        if (
            probe.get("truncated") is not False
            or type(probe.get("status")) is not int
            or not 100 <= probe["status"] <= 599
            or type(probe.get("body_bytes")) is not int
            or not 0 <= probe["body_bytes"] <= 65536
            or not isinstance(probe.get("body_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", probe["body_sha256"]) is None
        ):
            return "failed", "invalid_validation_observation"
    if attempt.scanner_source_state != "controlled_snapshot":
        return "inconclusive", "scanner_source_unverified"
    if any(
        p["status"] == 200
        and p["body_sha256"] == sha(marker.encode())
        and p["body_bytes"] == len(marker.encode())
        for p in probes
    ):
        return "confirmed", "fresh_canary_disclosed"
    return "inconclusive", "canary_not_disclosed"


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
    classification: Literal["confirmed", "inconclusive", "unsupported", "failed"] = "inconclusive"
    reason = "planning_prerequisites_missing"
    interrupted = False
    try:
        if row["status"] == "draft":
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
            classification, reason = classify(attempt)
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
