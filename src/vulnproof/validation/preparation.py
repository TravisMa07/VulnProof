"""Separately approved validation image preparation; runtime never builds images."""

import hashlib
import json
from importlib.resources import files
from pathlib import Path

from vulnproof.artifacts import read_local
from vulnproof.runner.docker import DockerClient, RunnerFailure
from vulnproof.runner.engine import inspection, publish
from vulnproof.runner.models import PreparedImage
from vulnproof.runner.profile import DAEMON_FORMAT, recipe_hash, verify_daemon, verify_image
from vulnproof.static.analysis import fixture_manifest

from .models import PROFILE, Approval, Preparation


def approval_bytes() -> bytes:
    return files("vulnproof.validation").joinpath("approvals.json").read_bytes()


def build_sources(variant: str) -> dict[str, str]:
    return {
        "Dockerfile": "fixtures/validation/Dockerfile",
        "runner_driver.py": "fixtures/validation/driver.py",
        "diagnostic_driver.py": "fixtures/runner/driver.py",
        "app.py": f"fixtures/cwe22/{variant}/app.py",
        "requirements.lock": "fixtures/cwe22/requirements.lock",
        "downloads/example.txt": "fixtures/cwe22/data/downloads/example.txt",
    }


def approval() -> Approval:
    value = Approval.model_validate_json(approval_bytes())
    known = {f.id for f in fixture_manifest().fixtures}
    if {r.fixture_id for r in value.recipes} != known or len(value.recipes) != len(known):
        raise ValueError("approval must cover exactly the reviewed fixture identities")
    if any(set(r.inputs) != set(build_sources("vulnerable")) for r in value.recipes):
        raise ValueError("approval has unexpected build inputs")
    return value


def select_image(record: Preparation, fixture_id: str, fingerprint: str | None) -> PreparedImage:
    if record.approval_sha256 != hashlib.sha256(approval_bytes()).hexdigest():
        raise RunnerFailure("stale_preparation", "Validation preparation uses another approval")
    recipes = {r.fixture_id: r for r in approval().recipes}
    known = {f.id: f.fingerprint for f in fixture_manifest().fixtures}
    for image in record.images:
        if (
            image.fixture_id not in recipes
            or image.source_fingerprint != known.get(image.fixture_id)
            or image.recipe_sha256 != recipe_hash(recipes[image.fixture_id])
        ):
            raise RunnerFailure("invalid_preparation", "Image does not match validation approval")
    selected = next((i for i in record.images if i.fixture_id == fixture_id), None)
    if selected is None or selected.source_fingerprint != fingerprint:
        raise RunnerFailure("image_source_mismatch", "No approved validation image for this source")
    return selected


def prepare_images(repository: Path, socket: Path, output: Path) -> Preparation:
    approved = approval()
    original = approval_bytes()
    contents = {}
    for variant in ("vulnerable", "patched"):
        identity = f"cwe22-{variant}-v1"
        recipe = next(r for r in approved.recipes if r.fixture_id == identity)
        content = {
            name: read_local(repository.absolute(), path, 1024 * 1024)
            for name, path in build_sources(variant).items()
        }
        if {
            name: hashlib.sha256(data).hexdigest() for name, data in content.items()
        } != recipe.inputs:
            raise RunnerFailure(
                "unapproved_build_inputs", "Review changed validation inputs before preparation"
            )
        contents[identity] = content
    output = output.absolute()
    output.mkdir(mode=0o700)
    (output / "diagnostics").mkdir(mode=0o700)
    client = DockerClient(socket, output, preparation=True)
    verify_daemon(json.loads(client.run(["info", DAEMON_FORMAT], "daemon")))
    images = []
    known = {f.id: f.fingerprint for f in fixture_manifest().fixtures}
    for identity, content in contents.items():
        context = output / "work" / identity
        context.mkdir()
        for name, data in content.items():
            path = context / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        iid = output / f"{identity}.iid"
        client.run(
            ["build", "--pull", "--iidfile", str(iid), str(context)],
            "build-" + identity,
            timeout=600,
        )
        image_id = read_local(output, iid.name, 128).decode("ascii").strip()
        verify_image(
            inspection(client.run(["image", "inspect", image_id], "image-" + identity)), image_id
        )
        if any(read_local(context, name, 1024 * 1024) != data for name, data in content.items()):
            raise RunnerFailure("build_inputs_changed", "Validation build context changed")
        images.append(
            PreparedImage(
                fixture_id=identity,
                source_fingerprint=known[identity],
                recipe_sha256=recipe_hash(
                    next(r for r in approved.recipes if r.fixture_id == identity)
                ),
                image_id=image_id,
            )
        )
    if approval_bytes() != original:
        raise RunnerFailure("approval_changed", "Validation approval changed during build")
    record = Preparation(
        schema_version="1.0",
        profile=PROFILE,
        approval_sha256=hashlib.sha256(original).hexdigest(),
        images=tuple(images),
    )
    publish(output / "prepared-images.json", record.model_dump_json(indent=2) + "\n")
    publish(
        output / "commands.json",
        json.dumps([c.model_dump(mode="json") for c in client.commands], indent=2) + "\n",
    )
    return record
