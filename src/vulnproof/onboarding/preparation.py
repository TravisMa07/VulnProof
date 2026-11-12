"""Prepare two source-bound immutable images; never use repository Dockerfiles."""

import hashlib
import json
import re
from importlib.resources import files
from pathlib import Path

from vulnproof.artifacts import read_local
from vulnproof.provenance.filesystem import open_root, scan_tree
from vulnproof.provenance.models import fingerprint
from vulnproof.runner.docker import DockerClient, RunnerFailure
from vulnproof.runner.engine import publish
from vulnproof.runner.repository import BASE, MAX_WHEEL, MAX_WHEELS
from vulnproof.static.repository import ScanInput

from .models import PreparedApplication
from .planning import verify_plan


def worker_bytes() -> bytes:
    return files("vulnproof.onboarding").joinpath("worker.py").read_bytes()


def recipes(directories: tuple[str, ...]) -> tuple[bytes, bytes]:
    common = f"FROM {BASE}\nENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1\n"
    ending = 'COPY worker.py /opt/vulnproof/worker.py\nUSER 10001:10001\nENTRYPOINT []\nHEALTHCHECK NONE\nCMD ["python", "-I", "-c", "raise SystemExit(\'Use an authorized application runner\')"]\n'
    app = (
        common
        + "COPY wheels/ /opt/wheels/\nCOPY requirements.lock /opt/requirements.lock\nRUN if test -s /opt/requirements.lock; then python -I -m pip --isolated install --no-index --no-deps --require-hashes --only-binary=:all: --no-cache-dir -r /opt/requirements.lock; fi && python -I -m pip --isolated check\nCOPY source/ /application/\n"
    )
    # Only trusted directory creation is performed here. App initialization runs under runtime restrictions.
    if directories:
        app += (
            "RUN "
            + json.dumps(
                [
                    "python",
                    "-I",
                    "-c",
                    "import os,json; [os.makedirs('/application/'+p,exist_ok=True) for p in json.loads("
                    + repr(json.dumps(directories))
                    + ")]",
                ]
            )
            + "\n"
        )
    return (app + ending + "WORKDIR /application\n").encode(), (
        common + ending + "WORKDIR /opt/vulnproof\n"
    ).encode()


def prepare_application(
    *,
    scan: Path,
    plan: Path,
    config: Path,
    wheelhouse: Path,
    socket: Path,
    output: Path,
    authorize_preparation: bool,
) -> PreparedApplication:
    if not authorize_preparation:
        raise RunnerFailure(
            "authorization_required", "Authorize application preparation explicitly"
        )
    scan, plan, config, wheelhouse, output = (
        p.absolute() for p in (scan, plan, config, wheelhouse, output)
    )
    try:
        raw, selected = verify_plan(scan, plan, config)
        application = selected.application
        if application is None or selected.gaps:
            raise RunnerFailure(
                "onboarding_incomplete", "Resolve onboarding prerequisites before preparation"
            )
        if any(
            a.resolve().is_relative_to(b.resolve())
            for source in (scan, plan, config, wheelhouse)
            for a, b in ((output, source), (source, output))
        ):
            raise RunnerFailure(
                "invalid_output", "Choose a new preparation directory separate from inputs"
            )
        wheels = {}
        for wheel in application.wheels:
            data = read_local(wheelhouse.absolute(), wheel.filename, MAX_WHEEL)
            if hashlib.sha256(data).hexdigest() != wheel.sha256:
                raise ValueError("Wheel digest mismatch")
            wheels[wheel.filename] = data
        if sum(map(len, wheels.values())) > MAX_WHEELS:
            raise ValueError("Wheel budget exceeded")
        app_recipe, observer_recipe = recipes(application.image_directories)
        if any(
            any(
                f.path == d or f.path.startswith(d + "/")
                for f in ScanInput.model_validate_json(
                    read_local(scan, "scan.json", 16 * 1024 * 1024)
                ).files
            )
            for d in application.image_directories
        ):
            raise ValueError("Synthetic image directories must be absent from captured source")
    except (OSError, ValueError) as exc:
        if isinstance(exc, RunnerFailure):
            raise
        raise RunnerFailure(
            "invalid_preparation_input",
            "Invalid onboarding plan, dependencies, or preparation destination",
        ) from exc
    output.mkdir(mode=0o700)
    (output / "diagnostics").mkdir()
    app_context, observer_context = output / "work/app", output / "work/observer"
    for directory in (app_context, observer_context):
        directory.mkdir(parents=True)
        (directory / "worker.py").write_bytes(worker_bytes())
    (app_context / "source").mkdir()
    with open_root(scan / "snapshot") as fd:
        tree = scan_tree(fd, app_context / "source")
    if tree.excluded_paths or fingerprint(tree.files) != selected.source_fingerprint:
        raise RunnerFailure("source_changed", "Source changed before build")
    (app_context / "wheels").mkdir()
    for name, data in wheels.items():
        (app_context / "wheels" / name).write_bytes(data)
    requirements = "".join(
        f"/opt/wheels/{w.filename} --hash=sha256:{w.sha256}\n" for w in application.wheels
    )
    (app_context / "requirements.lock").write_text(requirements)
    (app_context / "Dockerfile").write_bytes(app_recipe)
    (observer_context / "Dockerfile").write_bytes(observer_recipe)
    client = DockerClient(socket, output, preparation=True)
    image_ids = []
    for name, directory in (("application", app_context), ("observer", observer_context)):
        iid = output / (name + ".iid")
        client.run(
            [
                "build",
                "--network=none",
                "--pull=false",
                "--iidfile",
                str(iid.absolute()),
                str(directory.absolute()),
            ],
            "build-" + name,
            timeout=300,
        )
        image_id = iid.read_text().strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise RunnerFailure("invalid_image_id", "Build did not produce an immutable image ID")
        image_ids.append(image_id)
    with open_root(app_context / "source") as fd:
        after = scan_tree(fd)
    if after.files != tree.files or after.excluded_paths:
        raise RunnerFailure(
            "build_inputs_changed", "Private source copy changed during preparation"
        )
    expected = {
        app_context / "Dockerfile": app_recipe,
        observer_context / "Dockerfile": observer_recipe,
        app_context / "worker.py": worker_bytes(),
        observer_context / "worker.py": worker_bytes(),
        app_context / "requirements.lock": requirements.encode(),
    }
    expected.update({app_context / "wheels" / name: data for name, data in wheels.items()})
    if any(
        read_local(path.parent, path.name, MAX_WHEEL) != data for path, data in expected.items()
    ):
        raise RunnerFailure("build_inputs_changed", "Private preparation inputs changed")
    # Re-read identities after preparation so changed config/source cannot acquire a receipt.
    if verify_plan(scan, plan, config)[0] != raw:
        raise RunnerFailure("preparation_inputs_changed", "Onboarding inputs changed")
    receipt = PreparedApplication(
        plan_sha256=hashlib.sha256(raw).hexdigest(),
        scan_sha256=selected.scan_sha256,
        source_fingerprint=selected.source_fingerprint,
        app_image=image_ids[0],
        observer_image=image_ids[1],
        worker_sha256=hashlib.sha256(worker_bytes()).hexdigest(),
        recipe_sha256=hashlib.sha256(app_recipe + observer_recipe).hexdigest(),
        base_image=BASE,
        application=application,
    )
    publish(output / "prepared-application.json", receipt.model_dump_json(indent=2) + "\n")
    return receipt
