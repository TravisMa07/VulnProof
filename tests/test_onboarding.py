import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from tests.onboarding_support import inputs

from vulnproof.onboarding.models import Application
from vulnproof.onboarding.planning import inspect_application, verify_plan
from vulnproof.onboarding.preparation import prepare_application
from vulnproof.onboarding.runtime import exercise_application, verify_network
from vulnproof.runner.docker import RunnerFailure


def test_inspection_is_passive_and_configuration_optional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = inputs(tmp_path)

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("No processes allowed during inspection")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    report = inspect_application(args["scan"])
    assert report.application is None and report.gaps
    assert {o["path"] for o in report.observations} >= {"README.md", "pyproject.toml"}
    _, configured = verify_plan(**args)
    assert configured.application and not configured.gaps


@pytest.mark.parametrize("change", ["source", "plan", "config"])
def test_changed_inputs_rejected(tmp_path: Path, change: str) -> None:
    args = inputs(tmp_path)
    if change == "source":
        file = args["scan"] / "snapshot/app.py"
        file.chmod(0o600)
        file.write_text("raise RuntimeError()")
    elif change == "plan":
        data = json.loads(args["plan"].read_bytes())
        data["gaps"] = ["changed"]
        args["plan"].write_text(json.dumps(data))
    else:
        data = json.loads(args["config"].read_bytes())
        data["command"] = ["python", "changed.py"]
        args["config"].write_text(json.dumps(data))
    with pytest.raises(ValueError):
        verify_plan(**args)


@pytest.mark.parametrize(
    "field,value",
    [
        ("workdir", "../outside"),
        ("seeds", [{"path": "../outside", "text": "x"}]),
        ("environment", {"PATH": "/bad"}),
        (
            "controls",
            [
                {
                    "target": "http://external",
                    "expected_status": 200,
                    "expected_body_sha256": "a" * 64,
                }
            ],
        ),
    ],
)
def test_profile_boundaries(tmp_path: Path, field: str, value: Any) -> None:
    args = inputs(tmp_path)
    data = json.loads(args["config"].read_bytes())
    data[field] = value
    with pytest.raises(ValueError):
        Application.model_validate_json(json.dumps(data))


def test_authorization_precedes_docker(tmp_path: Path) -> None:
    args = inputs(tmp_path)
    with pytest.raises(RunnerFailure, match="Authorize"):
        prepare_application(
            **args,
            wheelhouse=tmp_path,
            socket=Path("/missing.sock"),
            output=tmp_path / "out",
            authorize_preparation=False,
        )
    with pytest.raises(RunnerFailure, match="Authorize"):
        exercise_application(
            **args,
            preparation=tmp_path / "missing",
            socket=Path("/missing.sock"),
            output=tmp_path / "out",
            authorize_execution=False,
        )
    assert not (tmp_path / "out").exists()


def test_network_policy_no_fallback() -> None:
    with pytest.raises(RunnerFailure):
        verify_network(
            {
                "Name": "test",
                "Driver": "bridge",
                "Internal": True,
                "Labels": {"vulnproof.onboarding": "test"},
                "Options": {},
            },
            "test",
        )


def test_preparation_identity_rejected_before_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hashlib

    from vulnproof.onboarding.models import PreparedApplication
    from vulnproof.onboarding.preparation import recipes
    from vulnproof.runner.repository import BASE

    args = inputs(tmp_path)
    raw, plan = verify_plan(**args)
    assert plan.application
    receipt = PreparedApplication(
        plan_sha256=hashlib.sha256(raw).hexdigest(),
        scan_sha256=plan.scan_sha256,
        source_fingerprint=plan.source_fingerprint,
        app_image="sha256:" + "a" * 64,
        observer_image="sha256:" + "b" * 64,
        worker_sha256="0" * 64,
        recipe_sha256=hashlib.sha256(b"".join(recipes(()))).hexdigest(),
        base_image=BASE,
        application=plan.application,
    )
    prepared = tmp_path / "prepared"
    prepared.mkdir()
    path = prepared / "prepared-application.json"
    path.write_text(receipt.model_dump_json())

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Invalid receipt must not reach Docker")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with pytest.raises(RunnerFailure, match="Preparation differs"):
        exercise_application(
            **args,
            preparation=path,
            socket=Path("/missing.sock"),
            output=tmp_path / "out",
            authorize_execution=True,
        )
    assert not (tmp_path / "out").exists()
