"""Validate actual retained benchmark evidence; never execute source while reporting."""

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from vulnproof.injections.models import Plans
from vulnproof.injections.reporting import verify_result

pytestmark = pytest.mark.skipif(
    not os.environ.get("VULNPROOF_INJECTION_BENCHMARK"),
    reason="Opt-in real injection benchmark evidence checks",
)


def benchmark() -> Path:
    return Path(os.environ["VULNPROOF_INJECTION_BENCHMARK"])


def test_three_fresh_runs_and_no_patched_confirmations() -> None:
    summary = json.loads((benchmark() / "benchmark.json").read_text())
    assert summary["passed"] and summary["runs"] == 3
    assert len(summary["attempts"]) == 18
    for capability in ("command", "sql", "template"):
        assert summary["static_counts"][capability]["vulnerable"] >= 1
        observations = [r for r in summary["attempts"] if r["capability"] == capability]
        assert len(observations) == 6 and all(r["passed"] and r["cleanup"] for r in observations)
        assert {r["classification"] for r in observations if r["variant"] == "patched"} == {
            "inconclusive"
        }


@pytest.mark.parametrize(
    "change", ["decision", "request", "nonce", "network_policy", "cleanup", "log"]
)
def test_edited_real_evidence_cannot_be_reported_as_confirmed(tmp_path: Path, change: str) -> None:
    original = benchmark()
    raw = (original / "plans.json").read_bytes()
    selected = Plans.model_validate_json(raw)
    directory = tmp_path / "attempt"
    shutil.copytree(
        original / "command-vulnerable/run-1", directory, ignore=shutil.ignore_patterns("work")
    )
    result = json.loads((directory / "result.json").read_text())
    attempt: dict[str, Any] = result["attempt"]

    def edit_log(stage: str, transform: Any) -> None:
        command = next(c for c in attempt["commands"] if c["stage"] == stage)
        path = directory / "execution" / command["log"]["path"]
        updated: bytes = transform(path.read_bytes())
        path.write_bytes(updated)
        command["log"]["sha256"] = hashlib.sha256(updated).hexdigest()
        command["log"]["size_bytes"] = len(updated)

    if change == "decision":
        result["decision"]["reason"] = "edited unsupported assertion"
    elif change == "request":
        attempt["observation"]["validation"]["attempts"][-1]["target"] = "/unrelated"
        edit_log("start", lambda _: json.dumps(attempt["observation"]).encode())
    elif change == "nonce":
        attempt["test_service_nonce"] = "b" * 32
    elif change == "network_policy":

        def alter(data: bytes) -> bytes:
            value = json.loads(data)
            value[0]["Internal"] = False
            return json.dumps(value).encode()

        edit_log("network-inspect", alter)
    elif change == "cleanup":
        edit_log("cleanup-absence", lambda _: b"container-still-present\n")
    elif change == "log":
        command = attempt["commands"][0]
        (directory / "execution" / command["log"]["path"]).write_text(
            "modified without updating digest"
        )
    (directory / "execution/result.json").write_text(json.dumps(attempt))
    (directory / "result.json").write_text(json.dumps(result))
    with pytest.raises(ValueError):
        verify_result(directory, selected, raw)
