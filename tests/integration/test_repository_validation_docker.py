"""Bounded repository validation with synthetic static evidence and real containers."""

import os
from pathlib import Path

import pytest
from tests.integration.test_repository_controls_docker import prepared_args

from vulnproof.validation.repository import validate_repository

pytestmark = pytest.mark.skipif(
    not os.environ.get("VULNPROOF_CONTROL_DOCKER_SOCKET"), reason="opt-in Docker validation"
)


@pytest.mark.parametrize(
    ("mode", "reason"),
    [
        ("normal", "scanner_source_unverified"),
        ("patched", "scanner_source_unverified"),
        ("wrong_body", "control_execution_or_cleanup_failed"),
    ],
)
def test_real_repository_validation(tmp_path: Path, mode: str, reason: str) -> None:
    args = prepared_args(tmp_path, "exports/web.py", mode)
    args.pop("authorize_execution")
    result = validate_repository(**args, authorize_validation=True)
    assert result.reason == reason, result.model_dump_json(indent=2)
    assert result.attempt and result.attempt.cleanup == "verified_absent"
    assert result.attempt.driver
    if mode == "wrong_body":
        assert result.attempt.driver.validation is None
    else:
        data = result.attempt.driver.validation
        assert data and data["outcome"] == "completed"
        if mode == "patched":
            assert all(p["status"] == 404 for p in data["probes"])
        else:
            from vulnproof.runner.repository import sha

            assert all(
                p["body_sha256"] == sha(data["canary_body"].encode()) for p in data["probes"]
            )


@pytest.mark.skipif(
    not (os.environ.get("VULNPROOF_TEST_SEMGREP") and os.environ.get("VULNPROOF_TEST_CODEQL")),
    reason="requires pinned Semgrep and CodeQL",
)
@pytest.mark.parametrize(
    ("mode", "expected"), [("normal", "confirmed"), ("patched", "inconclusive")]
)
def test_real_scanner_to_validation(tmp_path: Path, mode: str, expected: str) -> None:
    import json

    from vulnproof.cli import main
    from vulnproof.correlation.repository import correlate_repository
    from vulnproof.discovery.repository import discover
    from vulnproof.planning.repository import plan_repository
    from vulnproof.runner.repository import prepare_repository_image

    args = prepared_args(tmp_path, "exports/web.py", mode)
    scan, investigation = tmp_path / "real-scan", tmp_path / "real-analysis"
    assert (
        main(
            [
                "scan",
                "--repo",
                str(tmp_path / "checkout"),
                "--output",
                str(scan),
                "--semgrep-environment",
                os.environ["VULNPROOF_TEST_SEMGREP"],
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "investigate",
                "--scan",
                str(scan),
                "--output",
                str(investigation),
                "--codeql-bundle",
                os.environ["VULNPROOF_TEST_CODEQL"],
            ]
        )
        == 0
    )
    args.update(scan=scan, investigation=investigation)
    args["correlation"].write_text(correlate_repository(scan, investigation))
    args["discovery"].write_text(discover(scan, investigation, args["correlation"]))
    args["plan"].write_text(
        plan_repository(scan, investigation, args["correlation"], args["discovery"], args["config"])
    )
    plan = json.loads(args["plan"].read_bytes())
    draft = next(r for r in plan["findings"] if r["status"] == "draft")
    args["finding_id"] = draft["finding_id"]
    preparation = tmp_path / "scanner-prepared"
    prepare_repository_image(
        scan,
        tmp_path / "image.json",
        Path(os.environ["VULNPROOF_CONTROL_WHEELHOUSE"]),
        args["socket"],
        preparation,
    )
    args["preparation"] = preparation / "prepared-image.json"
    argv = ["validate-repository", "--authorize-validation"]
    names = {"socket": "docker-socket", "preparation": "prepared-image"}
    for key, value in args.items():
        if key != "authorize_execution":
            argv.extend(["--" + names.get(key, key.replace("_", "-")), str(value)])
    assert main(argv) == 0
    result = json.loads((args["output"] / "result.json").read_bytes())
    assert result["classification"] == expected, result
    assert result["scanner_source_state"] == "controlled_snapshot"
    assert result["attempt"]["cleanup"] == "verified_absent"


def test_missing_runtime_boundary(tmp_path: Path) -> None:
    import json

    from vulnproof.planning.repository import plan_repository

    args = prepared_args(tmp_path, "exports/web.py", "normal")
    config = json.loads(args["config"].read_bytes())
    config["endpoints"][0]["download_root"] = "/missing-boundary"
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
    assert result.classification == "failed" and result.reason == "boundary_unavailable"
    assert result.attempt and result.attempt.driver and result.attempt.driver.validation
    assert result.attempt.driver.validation["probes"] == []
    assert result.attempt.cleanup == "verified_absent"
