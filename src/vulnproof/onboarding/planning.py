"""Inspect captured metadata as bytes/JSON; never import or execute repository content."""

import ast
import hashlib
import json
import tomllib
from pathlib import Path

from vulnproof.artifacts import read_local
from vulnproof.discovery.flask import parse_module
from vulnproof.models.common import relative_path
from vulnproof.planning.repository import unique_fields
from vulnproof.provenance.filesystem import open_root, scan_tree
from vulnproof.provenance.models import fingerprint
from vulnproof.runner.docker import RunnerFailure
from vulnproof.static.repository import ScanInput

from .models import Application, OnboardingPlan


def read(path: Path, limit: int = 1024 * 1024) -> bytes:
    return read_local(path.absolute().parent, path.name, limit)


def verified_scan(scan: Path) -> tuple[bytes, ScanInput]:
    raw = read_local(scan, "scan.json", 16 * 1024 * 1024)
    manifest = ScanInput.model_validate_json(raw)
    with open_root(scan / "snapshot") as fd:
        tree = scan_tree(fd)
    if (
        tree.excluded_paths
        or tree.files != manifest.files
        or fingerprint(tree.files) != manifest.source_fingerprint
    ):
        raise RunnerFailure("source_changed", "Captured source does not match its manifest")
    return raw, manifest


def inspect_application(scan: Path, config: Path | None = None) -> OnboardingPlan:
    try:
        raw, manifest = verified_scan(scan.absolute())
        observations = []
        for file in manifest.files:
            name = Path(file.path).name.lower()
            if (
                name
                in {
                    "pyproject.toml",
                    "requirements.txt",
                    "package.json",
                    "dockerfile",
                    "compose.yaml",
                    "docker-compose.yml",
                    "openapi.json",
                    "openapi.yaml",
                }
                or name.startswith("readme")
                or name.startswith("test_")
            ):
                observations.append(
                    {
                        "path": file.path,
                        "kind": "test" if name.startswith("test_") else "metadata",
                        "sha256": file.sha256,
                    }
                )
        # Hints are declarations, not executable instructions or verified startup plans.
        for file in manifest.files:
            name = Path(file.path).name.lower()
            if name not in ("pyproject.toml", "package.json") or len(observations) >= 256:
                continue
            try:
                data = read_local(scan / "snapshot", file.path, 256 * 1024)
                info = (
                    tomllib.loads(data.decode()) if name == "pyproject.toml" else json.loads(data)
                )
                scripts = (
                    info.get("project", {}).get("scripts", {})
                    if name == "pyproject.toml"
                    else info.get("scripts", {})
                )
                if isinstance(scripts, dict):
                    for key, value in list(scripts.items())[:32]:
                        if isinstance(key, str) and isinstance(value, str):
                            observations.append(
                                {
                                    "path": file.path,
                                    "kind": "declared_startup_hint",
                                    "name": key[:128],
                                    "value": value[:512],
                                    "confidence": "operator_review_required",
                                }
                            )
            except OSError, ValueError, TypeError, AttributeError:
                observations.append({"path": file.path, "kind": "unreadable_metadata"})
        python_files = [f for f in manifest.files if f.path.endswith(".py")]
        for file in python_files[:128]:
            if len(observations) >= 256:
                break
            try:
                data = read_local(scan / "snapshot", file.path, 256 * 1024)
                module = parse_module(file.path, data)
                for handler in module.handlers[:16]:
                    for route in handler.routes:
                        observations.append(
                            {
                                "path": file.path,
                                "kind": "route_hint",
                                "handler": handler.name,
                                "method": route.method,
                                "route": route.path,
                                "confidence": "observed_syntax_only",
                            }
                        )
                tree = ast.parse(data)
                if any(
                    isinstance(n, ast.If)
                    and isinstance(n.test, ast.Compare)
                    and isinstance(n.test.left, ast.Name)
                    and n.test.left.id == "__name__"
                    for n in tree.body
                ):
                    observations.append(
                        {
                            "path": file.path,
                            "kind": "main_guard_hint",
                            "value": "python " + file.path,
                            "confidence": "operator_review_required",
                        }
                    )
            except OSError, ValueError, SyntaxError, RecursionError:
                continue
        if len(python_files) > 128 or len(observations) > 255:
            observations = observations[:255] + [
                {
                    "path": "",
                    "kind": "inspection_limit",
                    "value": "Other captured files remain in the source manifest; not all startup syntax was inspected",
                }
            ]
        gaps = []
        application = None
        config_bytes = None
        if config is None:
            gaps = [
                "startup_command_required",
                "dependency_wheel_hashes_required",
                "invocation_and_control_required",
                "synthetic_state_review_required",
            ]
        else:
            config_bytes = read(config)
            json.loads(config_bytes, object_pairs_hook=unique_fields)
            application = Application.model_validate_json(config_bytes)
            if application.workdir:
                relative_path(application.workdir)
                if not any(f.path.startswith(application.workdir + "/") for f in manifest.files):
                    raise ValueError("Working directory is outside captured source")
        return OnboardingPlan(
            scan_sha256=hashlib.sha256(raw).hexdigest(),
            source_fingerprint=manifest.source_fingerprint,
            configuration_sha256=hashlib.sha256(config_bytes).hexdigest() if config_bytes else None,
            application=application,
            observations=tuple(observations[:256]),
            gaps=tuple(gaps),
        )
    except (OSError, ValueError, KeyError, RecursionError) as exc:
        if isinstance(exc, RunnerFailure):
            raise
        raise RunnerFailure(
            "invalid_onboarding_input",
            "Expected consistent captured source and bounded application configuration",
        ) from exc


def verify_plan(scan: Path, plan: Path, config: Path | None) -> tuple[bytes, OnboardingPlan]:
    raw = read(plan, 4 * 1024 * 1024)
    json.loads(raw, object_pairs_hook=unique_fields)
    supplied = OnboardingPlan.model_validate_json(raw)
    if supplied != inspect_application(scan, config):
        raise RunnerFailure(
            "onboarding_plan_changed",
            "Onboarding plan differs from retained source or configuration",
        )
    return raw, supplied
