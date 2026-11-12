import hashlib
import json
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from tests.injection_support import inputs

from vulnproof.injections.models import Capability, Configuration, ValidationRequest
from vulnproof.injections.planning import plan_injections
from vulnproof.injections.reporting import write_injection_report
from vulnproof.injections.runtime import validate_injection
from vulnproof.investigation.assessment import ValidationEvidence, assess
from vulnproof.investigation.contracts import GetRequest, HttpInvocation
from vulnproof.onboarding.worker import injection_probes, injection_target
from vulnproof.validation.registry import VALIDATORS

KINDS = ("command", "sql", "template")


@pytest.mark.parametrize("kind", KINDS)
def test_planning_reconstructs_imported_evidence_without_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: Capability
) -> None:
    args = inputs(tmp_path, kind)

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("No application import or subprocess permitted")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = plan_injections(**args)
    assert result.scanner_source_state == "unverified"
    assert len(result.entries) == 1
    entry = result.entries[0]
    assert entry.status == "draft" and entry.path_ids and entry.result_id
    assert entry.endpoint and entry.endpoint.request.target("reader") == "/test?value=reader"
    missing = plan_injections(args["scan"], args["investigations"], None)
    assert missing.entries[0].reasons == ("endpoint_configuration_missing_or_ambiguous",)


@pytest.mark.parametrize(
    "change",
    [
        "source",
        "sarif",
        "inventory",
        "query",
        "path",
        "log",
        "config_route",
        "config_key",
        "partial",
        "missing_query",
    ],
)
def test_planning_rejects_edits_or_accounts_for_stopping_reason(
    tmp_path: Path, change: str
) -> None:
    args = inputs(tmp_path)
    analysis = args["investigations"]["command"]
    path = analysis / "investigation.json"
    report = json.loads(path.read_text())
    if change == "source":
        (args["scan"] / "snapshot/command/vulnerable/app.py").chmod(0o600)
        (args["scan"] / "snapshot/command/vulnerable/app.py").write_text(
            'raise RuntimeError("never import")'
        )
    elif change == "sarif":
        (args["scan"] / "diagnostics/raw.sarif").write_text("{}")
    elif change == "inventory":
        (args["scan"] / "inventory.json").write_text("{}")
    elif change == "query":
        report["query_sha256"] = "0" * 64
    elif change == "path":
        report["results"][0]["paths"][0]["path"]["locations"][0]["start_line"] = 1
    elif change == "log":
        (analysis / "diagnostics/query.log").write_text("edited")
    elif change.startswith("config_"):
        config = json.loads(args["config"].read_text())
        config["endpoints"][0]["request"]["route" if change == "config_route" else "query_key"] = (
            "/elsewhere" if change == "config_route" else "other"
        )
        args["config"].write_text(json.dumps(config))
    elif change == "partial":
        report["outcome"] = "partial"
    elif change == "missing_query":
        args["investigations"] = {}
    path.write_text(json.dumps(report))
    if change in ("config_route", "config_key", "partial", "missing_query"):
        result = plan_injections(**args)
        assert result.entries[0].status == "blocked" and result.entries[0].reasons
    else:
        with pytest.raises(ValueError):
            plan_injections(**args)


def observation(
    profile: GetRequest,
    value: str,
    marker: bool = False,
    body: bytes = b"",
    role: str | None = None,
) -> dict[str, Any]:
    return dict(
        method="GET",
        target=profile.target(value),
        request_body_bytes=0,
        request_body_sha256=hashlib.sha256(b"").hexdigest(),
        request_headers_sha256=hashlib.sha256(b"{}").hexdigest(),
        status=200,
        body_bytes=len(body),
        body_sha256=hashlib.sha256(body).hexdigest(),
        truncated=False,
        marker_present=marker,
        **({"role": role} if role else {}),
    )


def evidence(kind: Capability) -> ValidationEvidence:
    profile = GetRequest.model_validate_json(
        json.dumps(
            dict(
                schema_version="1.0",
                route="/test",
                query_key="value",
                fixed_query=[dict(name="fixed", value="space + 日本語")],
                control_value="reader",
            )
        )
    )
    nonce = "a" * 32
    attempts = [
        observation(
            profile,
            p["value"],
            p["role"] == "probe",
            b"VP_" + nonce.encode() if p["role"] == "probe" else b"",
            p["role"],
        )
        for p in injection_probes(kind, "reader", nonce)
    ]
    return ValidationEvidence(
        execution="completed",
        policy_verified=True,
        cleanup="verified_absent",
        control_valid=True,
        scanner_source_state="controlled_snapshot",
        invocation=HttpInvocation(
            request_target=profile.target("reader"),
            expected_body_sha256=hashlib.sha256(b"reader").hexdigest(),
            input_location="query",
            input_name="value",
            request_profile=profile,
        ),
        observations=dict(
            outcome="completed",
            validation=dict(
                capability=kind,
                nonce=nonce,
                control=observation(profile, "reader", False, b"reader"),
                control_valid=True,
                attempts=attempts,
            ),
        ),
    )


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(
    "case",
    [
        "confirmed",
        "unverified",
        "control_failed",
        "cleanup_failed",
        "no_marker",
        "edited_request",
        "reflection",
        "wrong_nonce",
        "truncated",
        "partial_probes",
        "wrong_capability",
        "http_error",
    ],
)
def test_oracle_admission_and_no_safety_semantics(kind: Capability, case: str) -> None:
    value = evidence(kind)
    assert value.observations
    validation = value.observations["validation"]
    if case == "unverified":
        value = replace(value, scanner_source_state="unverified")
    if case == "control_failed":
        value = replace(value, control_valid=False)
    if case == "cleanup_failed":
        value = replace(value, cleanup="unverified")
    if case == "no_marker" or case == "reflection":
        validation["attempts"][-1]["marker_present"] = False
    if case == "edited_request":
        validation["attempts"][-1]["target"] = "/unrelated"
    if case == "wrong_nonce":
        validation["nonce"] = "invalid"
    if case == "truncated":
        validation["attempts"][-1]["truncated"] = True
    if case == "partial_probes":
        validation["attempts"] = []
    if case == "wrong_capability":
        validation["capability"] = "unsupported"
    if case == "http_error":
        validation["attempts"][-1]["status"] = 500
    result = assess(f"{kind}-injection-v1", value, VALIDATORS)
    expected = (
        "confirmed"
        if case == "confirmed"
        else "inconclusive"
        if case in ("unverified", "no_marker", "reflection", "http_error")
        else "failed"
    )
    assert result.classification == expected
    assert "safe" not in result.reason or "no_safety" in result.reason


@pytest.mark.parametrize("kind", KINDS)
def test_fixed_bounded_payloads_do_not_contain_their_expected_marker(kind: Capability) -> None:
    probes = injection_probes(kind, "reader", "a" * 32)
    assert 1 <= len(probes) <= 2
    for probe in probes:
        assert probe["marker"] not in probe["value"]
    sample = evidence(kind).invocation.request_profile
    assert sample
    assert sample.target("reserved &? 空") == injection_target(
        sample.model_dump(mode="json"), "reserved &? 空"
    )


def test_unsupported_is_accounted_for_and_html_escapes(tmp_path: Path) -> None:
    args = inputs(tmp_path)
    raw = json.loads((args["scan"] / "diagnostics/raw.sarif").read_text())
    raw["runs"][0]["results"][0]["ruleId"] = "<script>alert(1)</script>"
    from vulnproof.correlation.repository import prepare_import

    scan = tmp_path / "unsupported"
    prepare_import(tmp_path / "checkout", None, json.dumps(raw).encode(), scan)
    args["scan"] = scan
    args["investigations"] = {}
    plans = plan_injections(**args)
    assert len(plans.entries) == 1 and plans.entries[0].reasons == ("unsupported_scanner_rule",)
    plan = tmp_path / "plans.json"
    plan.write_text(plans.model_dump_json())
    output = tmp_path / "report"
    write_injection_report(**args, plan=plan, validations=(), output=output)
    html = (output / "report.html").read_text()
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert json.loads((output / "report.json").read_text())["counts"]["findings"] == 1


def test_validation_authorization_precedes_docker_and_input_reads(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Authorize"):
        validate_injection(
            scan=tmp_path,
            investigations={},
            config=None,
            plan=tmp_path,
            finding_id="x",
            onboarding=tmp_path,
            application_config=tmp_path,
            preparation=tmp_path,
            socket=tmp_path,
            output=tmp_path,
            authorize_validation=False,
        )


@pytest.mark.parametrize("value", ["duplicate", "path", "sql_state"])
def test_configuration_rejects_unsupported_or_conflicting_inputs(value: str) -> None:
    from scripts.check_injection_benchmark import endpoint

    item = endpoint("sql", "vulnerable")
    if value == "duplicate":
        item["request"]["fixed_query"] = [{"name": "value", "value": "conflict"}]
    if value == "path":
        item["request"]["schema_version"] = "1.1"
    if value == "sql_state":
        item["synthetic_sql_state"] = False
    with pytest.raises(ValueError):
        Configuration.model_validate_json(json.dumps(dict(schema_version="1.0", endpoints=[item])))


@pytest.mark.parametrize("case", ["ambiguous", "no_path"])
def test_competing_sinks_and_missing_paths_cannot_be_configured_away(
    tmp_path: Path, case: str
) -> None:
    from tests.injection_support import rewrite_codeql

    args = inputs(tmp_path)
    rewrite_codeql(args, case)
    result = plan_injections(**args)
    assert result.entries[0].status == "blocked"
    assert result.entries[0].reasons == (
        ("ambiguous_sinks",) if case == "ambiguous" else ("analysis_partial",)
    )


def test_duplicates_preserve_each_occurrence(tmp_path: Path) -> None:
    from dataclasses import asdict

    from vulnproof.correlation.repository import snapshot_inventory
    from vulnproof.injections.planning import digest

    args = inputs(tmp_path)
    path = args["scan"] / "diagnostics/raw.sarif"
    value = json.loads(path.read_text())
    value["runs"][0]["results"].append(value["runs"][0]["results"][0])
    path.write_text(json.dumps(value))
    inv = snapshot_inventory(path.read_bytes(), args["scan"] / "snapshot", None)
    (args["scan"] / "inventory.json").write_text(json.dumps(asdict(inv)))
    metadata = json.loads((args["scan"] / "scan.json").read_text())
    metadata["sarif_sha256"] = digest(path.read_bytes())
    metadata["result_count"] = 2
    (args["scan"] / "scan.json").write_text(json.dumps(metadata))
    analysis = args["investigations"]["command"] / "investigation.json"
    report = json.loads(analysis.read_text())
    report["scan_sha256"] = digest((args["scan"] / "scan.json").read_bytes())
    analysis.write_text(json.dumps(report))
    result = plan_injections(**args)
    assert len(result.entries) == 2 and all(e.status == "draft" for e in result.entries)
    assert result.entries[0].finding_id != result.entries[1].finding_id
    assert result.entries[1].duplicate_of == result.entries[0].finding_id


def test_duplicate_config_fields_rejected(tmp_path: Path) -> None:
    args = inputs(tmp_path)
    data = args["config"].read_text()
    args["config"].write_text(data.replace('"endpoints":', '"endpoints":[], "endpoints":'))
    with pytest.raises(ValueError, match="Duplicate"):
        plan_injections(**args)


@pytest.mark.parametrize("kind", KINDS)
def test_cli_planning_and_offline_reporting(
    tmp_path: Path, kind: Capability, capsys: pytest.CaptureFixture[str]
) -> None:
    from vulnproof.cli import main

    args = inputs(tmp_path, kind)
    plan = tmp_path / "plans.json"
    common = [
        "--scan",
        str(args["scan"]),
        "--investigation",
        str(args["investigations"][kind]),
        "--config",
        str(args["config"]),
    ]
    assert main(["plan-injections", *common, "--output", str(plan)]) == 0
    assert json.loads(capsys.readouterr().out)["drafts"] == 1
    report = tmp_path / "report"
    assert main(["report-injections", *common, "--plan", str(plan), "--output", str(report)]) == 0
    row = json.loads((report / "report.json").read_text())["findings"][0]
    assert row["decision"] == {"classification": "inconclusive", "reason": "not_executed"}
    assert row["modeled_paths"] and (report / "report.html").exists()
    config = json.loads(args["config"].read_text())
    config["endpoints"][0]["request"]["route"] = "/changed"
    args["config"].write_text(json.dumps(config))
    assert (
        main(
            [
                "report-injections",
                *common,
                "--plan",
                str(plan),
                "--output",
                str(tmp_path / "rejected"),
            ]
        )
        == 2
    )
    assert "invalid_injection_evidence" in capsys.readouterr().err


def test_interruption_retains_failed_validation_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib

    from scripts.check_injection_benchmark import endpoint

    from vulnproof.injections.runtime import Result
    from vulnproof.onboarding.models import PreparedApplication
    from vulnproof.onboarding.planning import inspect_application
    from vulnproof.onboarding.runtime import ApplicationAttempt
    from vulnproof.runner.repository import BASE

    args = inputs(tmp_path)
    plans = plan_injections(**args)
    plan = tmp_path / "plans.json"
    plan.write_text(plans.model_dump_json())
    config = tmp_path / "application.json"
    config.write_text(
        json.dumps(
            dict(
                kind="http",
                command=["python", "app.py"],
                workdir="command/vulnerable",
                controls=[
                    dict(
                        target="/test?value=reader",
                        expected_status=200,
                        expected_body_sha256=hashlib.sha256(b"reader").hexdigest(),
                    )
                ],
            )
        )
    )
    onboarding = inspect_application(args["scan"], config)
    assert onboarding.application
    receipt = PreparedApplication(
        plan_sha256="0" * 64,
        scan_sha256=onboarding.scan_sha256,
        source_fingerprint=onboarding.source_fingerprint,
        app_image="sha256:" + "a" * 64,
        observer_image="sha256:" + "b" * 64,
        worker_sha256="0" * 64,
        recipe_sha256="0" * 64,
        base_image=BASE,
        application=onboarding.application,
    )
    request = ValidationRequest.model_validate_json(
        json.dumps(
            {
                k: v
                for k, v in endpoint("command", "vulnerable").items()
                if k in ("capability", "request", "control_sha256")
            }
        )
    )
    retained = ApplicationAttempt(
        schema_version="1.1",
        onboarding=onboarding,
        prepared=receipt,
        plan_sha256="0" * 64,
        preparation_sha256="0" * 64,
        source_fingerprint=onboarding.source_fingerprint,
        evidence_level="application",
        outcome="interrupted",
        reason="interrupted",
        policy_verified=False,
        test_service_nonce="a" * 32,
        network="vulnproof-app-test",
        containers=(),
        observation=None,
        application_status=None,
        cleanup={},
        commands=(),
        validation_request=request,
    )

    def interrupt(**kwargs: Any) -> None:
        output = kwargs["output"]
        output.mkdir()
        (output / "result.json").write_text(retained.model_dump_json())
        raise KeyboardInterrupt

    monkeypatch.setattr(
        importlib.import_module("vulnproof.injections.runtime"), "exercise_application", interrupt
    )
    with pytest.raises(KeyboardInterrupt):
        validate_injection(
            **args,
            plan=plan,
            finding_id=plans.entries[0].finding_id,
            onboarding=tmp_path / "onboarding.json",
            application_config=config,
            preparation=tmp_path / "preparation/prepared.json",
            socket=tmp_path / "unused.sock",
            output=tmp_path / "attempt",
            authorize_validation=True,
        )
    result = Result.model_validate_json((tmp_path / "attempt/result.json").read_bytes())
    assert (
        result.decision.classification == "failed"
        and result.attempt
        and result.attempt.outcome == "interrupted"
    )
