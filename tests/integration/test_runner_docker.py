"""Real Linux containers with explicitly synthetic static evidence; no CWE-22 probes."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from tests.static_pipeline import codeql_sarif, prepare, scanner_sarif

from vulnproof.correlation import correlate
from vulnproof.planning import create_plans
from vulnproof.runner import RunnerFailure, run_diagnostics
from vulnproof.runner.docker import DockerClient

pytestmark = pytest.mark.runner_docker


def arguments(root: Path, config: pytest.Config, variant: str) -> dict[str, Any]:
    # Authored path to an in-range fixture location tests orchestration, not real analysis.
    # The patched fixture also receives synthetic input solely to exercise its diagnostic image.
    capture, analysis = prepare(
        root, scanner_sarif(line=14), codeql_sarif(line=14), variant=variant
    )
    correlation = root / "synthetic-correlation.json"
    correlation.write_text(correlate(capture, analysis).model_dump_json())
    plan = root / "synthetic-plan.json"
    document = create_plans(capture, analysis, correlation)
    plan.write_text(document.model_dump_json(indent=2))
    return dict(
        capture=capture,
        analysis=analysis,
        correlation=correlation,
        plan=plan,
        preparation=Path(config.getoption("--runner-prepared-images")),
        socket=Path(config.getoption("--runner-docker-socket")),
        finding_id=document.findings[0].finding_id,
        output=root / "attempt",
        authorize_execution=True,
    )


def retain(output: Path, label: str) -> None:
    # Bounded diagnostics only; never databases or source trees in CI artifacts.
    identity = json.loads((output / "reservation.json").read_bytes())["container_name"]
    destination = Path.cwd() / ".cache/runner-check" / (label + "-" + identity)
    destination.mkdir(parents=True, exist_ok=True)
    for name in ("attempt.json", "reservation.json"):
        if (output / name).exists():
            shutil.copyfile(output / name, destination / name)
    if (output / "diagnostics").exists():
        shutil.copytree(output / "diagnostics", destination / "diagnostics", dirs_exist_ok=True)


@pytest.mark.parametrize("variant", ["vulnerable", "patched"])
def test_real_fixture_diagnostics(
    tmp_path: Path, pytestconfig: pytest.Config, variant: str
) -> None:
    args = arguments(tmp_path, pytestconfig, variant)
    report = run_diagnostics(**args)
    retain(args["output"], variant)
    assert report.execution == "completed" and report.cleanup == "verified_absent"
    assert report.policy_verified and report.driver is not None
    assert all(report.driver.checks.values())
    inspection = next(c for c in report.commands if c.stage == "container-inspect")
    observed = json.loads((args["output"] / inspection.log.path).read_bytes())[0]
    assert observed["HostConfig"]["Memory"] == 268435456
    assert observed["HostConfig"]["NetworkMode"] == "none"
    assert not observed["HostConfig"].get("Binds")


@pytest.mark.parametrize("mode", ["timeout", "output", "policy"])
def test_real_failure_cleanup(
    tmp_path: Path, pytestconfig: pytest.Config, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    args = arguments(tmp_path, pytestconfig, "vulnerable")
    original = DockerClient.run

    def constrained(self: DockerClient, command: list[str], stage: str, **kwargs: Any) -> bytes:
        if stage == "start":
            if mode == "timeout":
                kwargs["timeout"] = 0.001
            elif mode == "output":
                self.remaining = 16
        return original(self, command, stage, **kwargs)

    monkeypatch.setattr(DockerClient, "run", constrained)
    if mode == "policy":

        def reject(*args: object) -> None:
            raise RunnerFailure(
                "test_policy_rejection", "Synthetic rejection before driver startup"
            )

        monkeypatch.setattr("vulnproof.runner.engine.verify_container", reject)
    report = run_diagnostics(**args)
    retain(args["output"], mode)
    assert report.execution != "completed" and report.cleanup == "verified_absent"
    if mode == "policy":
        assert not any(c.stage == "start" for c in report.commands)
