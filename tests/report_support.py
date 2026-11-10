"""Explicit illustrative records for report tests; no runtime validation claims."""

import hashlib
import json
from pathlib import Path
from typing import Any

from tests.test_validation import driver

from vulnproof.models import EvidenceBundle
from vulnproof.runner.models import PreparedImage
from vulnproof.validation.models import PROFILE, Attempt, Driver

ROOT = Path(__file__).resolve().parents[1]


def sample(root: Path, name: str = "confirmed") -> dict[str, Any]:
    root.mkdir(parents=True)
    data: dict[str, Any] = json.loads((ROOT / f"docs/examples/evidence/{name}.json").read_bytes())
    for ref in data.get("artifacts", []):
        path = root / ref["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        content = b"Illustrative report-test evidence only\n"
        path.write_bytes(content)
        ref.update(sha256=hashlib.sha256(content).hexdigest(), size_bytes=len(content))
    (root / "result.json").write_text(json.dumps(data))
    return data


def save(root: Path, data: dict[str, Any]) -> None:
    EvidenceBundle.model_validate_json(json.dumps(data))
    (root / "result.json").write_text(json.dumps(data))


def with_attempt(root: Path, *, cleanup: str = "verified_absent") -> dict[str, Any]:
    data = sample(root)
    finding = data["finding"]
    execution = data["execution_evidence"][0]
    snapshot = data["snapshots"][0]
    image = PreparedImage(
        fixture_id="cwe22-vulnerable-v1",
        source_fingerprint=snapshot["fingerprint"],
        image_id=execution["image_id"],
        recipe_sha256="a" * 64,
    )
    attempt_data = dict(
        schema_version="1.0",
        profile=PROFILE,
        attempt_id="illustrative:attempt",
        fixture_id=image.fixture_id,
        image=image.model_dump(mode="json"),
        preparation_sha256="b" * 64,
        approval_sha256="c" * 64,
        plan_sha256="d" * 64,
        finding_id=finding["id"],
        candidate_result_id="illustrative:candidate",
        path_id=execution["static_path_id"],
        execution_authorized=True,
        authorization_scope="fixture_cwe22_validation_only",
        policy_verified=True,
        execution="completed",
        cleanup=cleanup,
        exit_code=0,
        oom_killed=False,
        driver=Driver.model_validate_json(json.dumps(driver())).model_dump(mode="json"),
        commands=[],
        reasons=[],
    )
    attempt = Attempt.model_validate_json(json.dumps(attempt_data))
    content = attempt.model_dump_json().encode()
    ref = data["artifacts"][0]
    ref.update(
        id="validation:attempt", sha256=hashlib.sha256(content).hexdigest(), size_bytes=len(content)
    )
    execution["artifact_ids"] = [ref["id"]]
    (root / ref["path"]).write_bytes(content)
    if cleanup == "unverified":
        data["assessment"]["classification"] = "failed"
        data["assessment"]["reasons"] = [
            {
                "code": "cleanup_unverified",
                "message": "Illustrative cleanup failure after observed disclosure",
            }
        ]
    save(root, data)
    return data
