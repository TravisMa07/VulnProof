import json
from pathlib import Path

import pytest
from tests.test_repository_controls import setup

from vulnproof.runner.docker import RunnerFailure
from vulnproof.runner.repository import sha
from vulnproof.validation.repository import classify, validate_repository


def test_authorization_is_separate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args, _ = setup(tmp_path, monkeypatch)
    args.pop("authorize_execution")
    with pytest.raises(RunnerFailure, match="authorization"):
        validate_repository(**args, authorize_validation=False)
    assert not args["output"].exists()


def test_missing_probe_evidence_cannot_confirm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args, _ = setup(tmp_path, monkeypatch)
    args.pop("authorize_execution")
    result = validate_repository(**args, authorize_validation=True)
    assert result.classification == "failed" and result.reason == "validation_missing"
    assert (args["output"] / "result.json").exists()
    assert result.attempt and result.attempt.authorization_scope == "repository_cwe22_validation"


def test_classifier_requires_provenance_control_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os
    from urllib.parse import urlencode

    from tests.repository_control_support import control_inputs
    from tests.runner_support import fake_docker
    from tests.test_repository_controls import driver

    from vulnproof.runner.repository import COMMAND

    args = control_inputs(tmp_path)
    marker = "VulnProof:" + "a" * 64 + "\n"
    path = "/tmp/vulnproof/" + "b" * 32 + ".txt"
    probes = [
        {
            "kind": kind,
            "request_target": "/export?" + urlencode({"document": value}),
            "status": 200,
            "body_bytes": len(marker),
            "body_sha256": sha(marker.encode()),
            "truncated": False,
        }
        for kind, value in (
            ("parent_traversal", os.path.relpath(path, "/application")),
            ("absolute_path", path),
        )
    ]
    observation = driver() | {
        "validation": {
            "outcome": "completed",
            "reason": "probes_completed",
            "canary_body": marker,
            "canary_path": path,
            "initially_absent": True,
            "download_root": "/application",
            "probes": probes,
        }
    }
    fake_docker(
        tmp_path,
        monkeypatch,
        repository=True,
        prepared_command=COMMAND,
        repository_driver=observation,
    )
    args.pop("authorize_execution")
    result = validate_repository(**args, authorize_validation=True)
    assert result.classification == "inconclusive" and result.reason == "scanner_source_unverified"
    assert result.attempt
    # Authored provenance here tests classification invariants, not scanner authenticity.
    controlled = result.attempt.model_copy(update={"scanner_source_state": "controlled_snapshot"})
    assert classify(controlled) == ("confirmed", "fresh_canary_disclosed")
    assert classify(controlled.model_copy(update={"cleanup": "unverified"}))[0] == "failed"
    assert result.attempt.driver
    validation = result.attempt.driver.validation
    assert validation
    validation["probes"][0]["request_target"] = "/other"
    assert classify(controlled)[0] == "failed"


def test_blocked_finding_retains_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vulnproof.planning.repository import plan_repository

    args, fake = setup(tmp_path, monkeypatch)
    config = json.loads(args["config"].read_bytes())
    config["endpoints"][0].pop("control_sha256")
    args["config"].write_text(json.dumps(config))
    args["plan"].write_text(
        plan_repository(
            args["scan"],
            args["investigation"],
            args["correlation"],
            args["discovery"],
            args["config"],
        )
    )
    args.pop("authorize_execution")
    result = validate_repository(**args, authorize_validation=True)
    assert result.classification == "inconclusive" and result.attempt is None
    assert not (fake / "calls.jsonl").exists()
