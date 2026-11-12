"""Opt-in real observer failure gates; application code is imported only in Docker."""

import json
import os
from pathlib import Path

import pytest
from scripts.check_injection_benchmark import application_profile, endpoint

from vulnproof.correlation.repository import prepare_import
from vulnproof.injections.models import Capability, ValidationRequest
from vulnproof.onboarding.planning import inspect_application
from vulnproof.onboarding.preparation import prepare_application
from vulnproof.onboarding.runtime import exercise_application

pytestmark = pytest.mark.skipif(
    not os.environ.get("VULNPROOF_CONTROL_DOCKER_SOCKET")
    or not os.environ.get("VULNPROOF_CONTROL_WHEELHOUSE"),
    reason="Opt-in injection Docker controls require a socket and Linux fixture wheels",
)
ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("kind", ["command", "sql", "template"])
def test_failed_validation_control_stops_all_probes(tmp_path: Path, kind: Capability) -> None:

    source = ROOT / "fixtures/injections"
    scan = tmp_path / "scan"
    prepare_import(source, None, b'{"version":"2.1.0","runs":[]}', scan)
    wheels = Path(os.environ["VULNPROOF_CONTROL_WHEELHOUSE"]).absolute()
    config = tmp_path / "application.json"
    config.write_text(json.dumps(application_profile(kind, "vulnerable", wheels)))
    plan = tmp_path / "onboarding.json"
    plan.write_text(inspect_application(scan, config).model_dump_json())
    preparation = tmp_path / "preparation"
    socket = Path(os.environ["VULNPROOF_CONTROL_DOCKER_SOCKET"])
    prepare_application(
        scan=scan,
        plan=plan,
        config=config,
        wheelhouse=wheels,
        socket=socket,
        output=preparation,
        authorize_preparation=True,
    )
    request = ValidationRequest.model_validate_json(
        json.dumps(
            {
                k: v
                for k, v in endpoint(kind, "vulnerable").items()
                if k in ("capability", "request", "control_sha256")
            }
        )
    )
    request = request.model_copy(update={"control_sha256": "0" * 64})
    attempt = exercise_application(
        scan=scan,
        plan=plan,
        config=config,
        preparation=preparation / "prepared-application.json",
        socket=socket,
        output=tmp_path / "run",
        authorize_execution=True,
        validation=request,
    )
    assert attempt.outcome == "failed" and all(attempt.cleanup.values())
    assert attempt.observation and attempt.observation["validation"]["attempts"] == []
    assert attempt.observation["reason"] == "validation_control_failed"
    assert attempt.observation["validation"]["control_valid"] is False


def test_failed_sql_negative_control_stops_the_positive_probe(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("""from flask import Flask
app=Flask(__name__,static_folder=None)
@app.get('/ready')
def ready():return 'ready'
@app.get('/test')
def test():return 'reader'
app.run(host='0.0.0.0',port=8000,use_reloader=False)
""")
    scan = tmp_path / "scan"
    prepare_import(source, None, b'{"version":"2.1.0","runs":[]}', scan)
    wheels = Path(os.environ["VULNPROOF_CONTROL_WHEELHOUSE"]).absolute()
    profile = application_profile("sql", "vulnerable", wheels)
    profile["workdir"] = None
    config = tmp_path / "application.json"
    config.write_text(json.dumps(profile))
    plan = tmp_path / "onboarding.json"
    plan.write_text(inspect_application(scan, config).model_dump_json())
    preparation = tmp_path / "preparation"
    socket = Path(os.environ["VULNPROOF_CONTROL_DOCKER_SOCKET"])
    prepare_application(
        scan=scan,
        plan=plan,
        config=config,
        wheelhouse=wheels,
        socket=socket,
        output=preparation,
        authorize_preparation=True,
    )
    request = ValidationRequest.model_validate_json(
        json.dumps(
            {
                k: v
                for k, v in endpoint("sql", "vulnerable").items()
                if k in ("capability", "request", "control_sha256")
            }
        )
    )
    attempt = exercise_application(
        scan=scan,
        plan=plan,
        config=config,
        preparation=preparation / "prepared-application.json",
        socket=socket,
        output=tmp_path / "run",
        authorize_execution=True,
        validation=request,
    )
    assert attempt.outcome == "failed" and all(attempt.cleanup.values())
    assert attempt.observation and attempt.observation["reason"] == "sql_negative_control_failed"
    assert [p["role"] for p in attempt.observation["validation"]["attempts"]] == ["negative"]
