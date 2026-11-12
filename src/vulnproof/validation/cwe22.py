"""CWE-22 oracle: interpret complete bounded observations, never run the application."""

import hashlib
import os
import re
from pathlib import Path
from urllib.parse import urlencode

from vulnproof.investigation.assessment import ValidationEvidence
from vulnproof.investigation.contracts import Decision


def assess_path_traversal(evidence: ValidationEvidence) -> Decision:
    observed = evidence.observations
    assert observed is not None
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
        return Decision(classification="failed", reason="invalid_validation_observation")
    expected_targets = [
        evidence.invocation.request_profile.target(value)
        if evidence.invocation.request_profile is not None
        else evidence.invocation.request_target.split("?", 1)[0]
        + "?"
        + urlencode({evidence.invocation.input_name: value})
        for value in (os.path.relpath(path, root), path)
    ]
    if [p.get("request_target") for p in probes] != expected_targets:
        return Decision(classification="failed", reason="probe_request_mismatch")
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
            return Decision(classification="failed", reason="invalid_validation_observation")
    if evidence.scanner_source_state != "controlled_snapshot":
        return Decision(classification="inconclusive", reason="scanner_source_unverified")
    if any(
        p["status"] == 200
        and p["body_sha256"] == hashlib.sha256(marker.encode()).hexdigest()
        and p["body_bytes"] == len(marker.encode())
        for p in probes
    ):
        return Decision(classification="confirmed", reason="fresh_canary_disclosed")
    return Decision(classification="inconclusive", reason="canary_not_disclosed")
