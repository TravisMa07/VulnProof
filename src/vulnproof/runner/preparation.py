"""Fixed trusted repository inputs; preparation is separate from runtime execution."""

import hashlib
import json
from pathlib import Path

from vulnproof.artifacts import read_local
from vulnproof.static.analysis import fixture_manifest

from .docker import DockerClient, RunnerFailure
from .engine import inspection, publish
from .models import PreparationRecord, PreparedImage
from .profile import (
    DAEMON_FORMAT,
    approval_bytes,
    recipe_hash,
    runner_approval,
    verify_daemon,
    verify_image,
)


def build_sources(variant: str) -> dict[str, str]:
    return {
        "Dockerfile": "fixtures/runner/Dockerfile",
        "runner_driver.py": "fixtures/runner/driver.py",
        "app.py": f"fixtures/cwe22/{variant}/app.py",
        "requirements.lock": "fixtures/cwe22/requirements.lock",
        "downloads/example.txt": "fixtures/cwe22/data/downloads/example.txt",
    }


def prepare_images(repository: Path, socket: Path, output: Path) -> PreparationRecord:
    approval = runner_approval()
    approved_bytes = approval_bytes()
    contents: dict[str, dict[str, bytes]] = {}
    fixtures = {f.id: f.fingerprint for f in fixture_manifest().fixtures}
    for variant in ("vulnerable", "patched"):
        fixture_id = f"cwe22-{variant}-v1"
        recipe = next(r for r in approval.recipes if r.fixture_id == fixture_id)
        contents[fixture_id] = {
            name: read_local(repository.absolute(), source, 1024 * 1024)
            for name, source in build_sources(variant).items()
        }
        if {
            name: hashlib.sha256(data).hexdigest() for name, data in contents[fixture_id].items()
        } != recipe.inputs:
            raise RunnerFailure(
                "unapproved_build_inputs",
                "Build inputs changed; review and update installed runner approvals",
            )
    output = output.absolute()
    output.mkdir(mode=0o700)
    (output / "diagnostics").mkdir(mode=0o700)
    client = DockerClient(socket, output, preparation=True)
    verify_daemon(json.loads(client.run(["info", DAEMON_FORMAT], "daemon")))
    images = []
    for fixture_id, content in contents.items():
        context = output / "work" / fixture_id
        context.mkdir()
        for name, data in content.items():
            path = context / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        iid = output / f"{fixture_id}.iid"
        client.run(
            ["build", "--pull", "--iidfile", str(iid), str(context)],
            "build-" + fixture_id,
            timeout=600,
        )
        image_id = read_local(output, iid.name, 128).decode("ascii").strip()
        recipe = next(r for r in approval.recipes if r.fixture_id == fixture_id)
        if any(read_local(context, name, 1024 * 1024) != data for name, data in content.items()):
            raise RunnerFailure(
                "build_inputs_changed", "Narrow build context changed during preparation"
            )
        image = PreparedImage(
            fixture_id=fixture_id,
            source_fingerprint=fixtures[fixture_id],
            recipe_sha256=recipe_hash(recipe),
            image_id=image_id,
        )
        verify_image(
            inspection(client.run(["image", "inspect", image_id], "inspect-" + fixture_id)),
            image_id,
        )
        images.append(image)
    if approval_bytes() != approved_bytes:
        raise RunnerFailure("approval_changed", "Installed approval changed during preparation")
    record = PreparationRecord(
        schema_version="1.0",
        profile="fixture-diagnostics-v1",
        approval_sha256=hashlib.sha256(approved_bytes).hexdigest(),
        images=tuple(images),
    )
    publish(output / "prepared-images.json", record.model_dump_json(indent=2) + "\n")
    publish(
        output / "commands.json",
        json.dumps([c.model_dump(mode="json") for c in client.commands], indent=2) + "\n",
    )
    return record
