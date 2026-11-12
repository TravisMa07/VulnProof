import json
from dataclasses import replace
from pathlib import Path

import pytest
from tests.test_repository_controls import setup

from vulnproof.investigation.assessment import ValidationEvidence, assess
from vulnproof.investigation.capabilities import QUERIES, RULES, mapping_for
from vulnproof.investigation.contracts import Decision, ExecutionContext, GetRequest, HttpInvocation
from vulnproof.runner.control_driver import VALIDATION_HANDLERS, observe
from vulnproof.runner.controls import RepositoryControlAttempt, check_repository
from vulnproof.validation.registry import VALIDATORS


def evidence() -> ValidationEvidence:
    invocation = HttpInvocation(
        request_target="/action?input=normal",
        expected_body_sha256="a" * 64,
        input_location="query",
        input_name="input",
    )
    return ValidationEvidence(
        execution="completed",
        policy_verified=True,
        cleanup="verified_absent",
        control_valid=True,
        scanner_source_state="controlled_snapshot",
        invocation=invocation,
        observations={"outcome": "completed", "different_oracle": True},
    )


def test_second_oracle_uses_shared_gates_without_traversal_records() -> None:
    calls = []

    def another(item: ValidationEvidence) -> Decision:
        calls.append(item.observations)
        assert item.observations and item.observations["different_oracle"]
        return Decision(classification="confirmed", reason="test_observation")

    registry = {"test-only": another}
    assert assess("test-only", evidence(), registry).classification == "confirmed"
    assert len(calls) == 1
    for changed in [
        replace(evidence(), control_valid=False),
        replace(evidence(), policy_verified=False),
        replace(evidence(), cleanup="unverified"),
        replace(evidence(), execution="timed_out"),
    ]:
        assert assess("test-only", changed, registry).classification == "failed"
    assert len(calls) == 1
    assert (
        assess(
            "test-only", replace(evidence(), scanner_source_state="unverified"), registry
        ).classification
        == "inconclusive"
    )
    assert assess("unknown", evidence(), registry).classification == "unsupported"
    # Test-only callback is not registered as a supported product capability.
    assert "test-only" not in VALIDATORS


def test_installed_registry_is_consistent() -> None:
    assert len({(r.producer, r.rule_id) for r in RULES}) == len(RULES)
    for mapping in RULES:
        assert mapping.query_id in QUERIES
        assert mapping.validator_id in VALIDATORS and mapping.validator_id in VALIDATION_HANDLERS
        assert mapping_for(mapping.producer, mapping.rule_id) == mapping
    assert mapping_for("other", RULES[0].rule_id) is None
    assert mapping_for("Semgrep OSS", "unknown") is None


def test_unknown_worker_stops_before_restrictions_or_import() -> None:
    observed = observe({"validation": True, "validator_id": "repository.supplied.module"})
    assert observed["reason"] == "unsupported_validator"
    assert observed["application_started"] is False and observed["checks"] == {}


def test_request_contract_round_trip() -> None:
    request = GetRequest.model_validate_json(
        json.dumps(
            dict(
                schema_version="1.0",
                route="/file",
                query_key="name",
                control_value="manual.txt",
                fixed_query=[{"name": "version", "value": ""}],
            )
        )
    )
    assert request.target("../marker") == "/file?version=&name=..%2Fmarker"
    assert GetRequest.model_validate_json(request.model_dump_json()) == request


def test_execution_context_is_bound_and_old_attempts_remain_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args, _ = setup(tmp_path, monkeypatch)
    attempt = check_repository(**args)
    assert attempt.schema_version == "1.2" and attempt.context
    assert (
        ExecutionContext.model_validate_json(attempt.context.model_dump_json()) == attempt.context
    )
    data = json.loads(attempt.model_dump_json())
    data["context"]["application"]["image_id"] = "sha256:" + "b" * 64
    with pytest.raises(ValueError, match="provenance"):
        RepositoryControlAttempt.model_validate_json(json.dumps(data))
    data = json.loads(attempt.model_dump_json())
    data["context"]["invocation"]["request_target"] = "/other"
    with pytest.raises(ValueError, match="Invocation context"):
        RepositoryControlAttempt.model_validate_json(json.dumps(data))
    data = json.loads(attempt.model_dump_json())
    data.pop("context")
    data["schema_version"] = "1.0"
    restored = RepositoryControlAttempt.model_validate_json(json.dumps(data))
    assert restored.context is None and restored.request == attempt.request
