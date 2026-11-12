"""Opt-in pinned upstream example onboarding. Does not clone or execute code on the host."""

import argparse
import base64
import hashlib
import json
from pathlib import Path

from vulnproof.correlation.repository import prepare_import
from vulnproof.onboarding.planning import inspect_application
from vulnproof.onboarding.preparation import prepare_application
from vulnproof.onboarding.runtime import exercise_application
from vulnproof.provenance.git import _command, checkout_head
from vulnproof.runner.docker import RunnerFailure
from vulnproof.runner.engine import publish

PINS = {
    "flask": "49943b5a94413a530761350f04e896f76e8d620e",
    "werkzeug": "0f43c6ebd426039e4b99ec22535c2c8a2ec2f69f",
}


def profiles(wheelhouse: Path) -> dict[str, dict[str, object]]:
    wheels = [
        {"filename": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        for p in sorted(wheelhouse.glob("*.whl"))
    ]
    if not wheels:
        raise RunnerFailure(
            "wheelhouse_required", "Provide the pinned Linux Flask dependency wheelhouse"
        )
    create = "import os\nfrom flaskr import create_app\napp=create_app({'DATABASE':os.environ['VULNPROOF_STATE_DIR']+'/flask.sqlite','SECRET_KEY':'VulnProof synthetic key'})\n"
    initialize = (
        create
        + "from flaskr.db import init_db, get_db\nfrom werkzeug.security import generate_password_hash\nwith app.app_context():\n init_db()\n db=get_db()\n db.execute('insert into user(username,password) values(?,?)',('reader',generate_password_hash('synthetic-password')))\n db.commit()\n assert db.execute('select count(*) from user').fetchone()[0] == 1\n"
    )
    redirect = b'<!doctype html>\n<html lang=en>\n<title>Redirecting...</title>\n<h1>Redirecting...</h1>\n<p>You should be redirected automatically to the target URL: <a href="/">/</a>. If not, click the link.\n'
    return {
        "flask": dict(
            schema_version="1.0",
            kind="http",
            wheels=wheels,
            workdir="examples/tutorial",
            image_directories=["examples/tutorial/instance"],
            command=[
                "python",
                "-c",
                create + "app.run(host='0.0.0.0',port=8000,use_reloader=False)",
            ],
            initialize=[["python", "-c", initialize]],
            readiness={"target": "/hello", "status": 200},
            controls=[
                {
                    "target": "/hello",
                    "expected_status": 200,
                    "expected_body_sha256": hashlib.sha256(b"Hello, World!").hexdigest(),
                },
                {
                    "method": "POST",
                    "target": "/auth/login",
                    "headers": [
                        {"name": "Content-Type", "value": "application/x-www-form-urlencoded"}
                    ],
                    "body": "username=reader&password=synthetic-password",
                    "expected_status": 302,
                    "expected_body_sha256": hashlib.sha256(redirect).hexdigest(),
                },
            ],
        ),
        "werkzeug": dict(
            schema_version="1.0",
            kind="http",
            wheels=wheels,
            workdir="examples",
            command=[
                "python",
                "-c",
                "from httpbasicauth import Application\nfrom werkzeug.serving import run_simple\nrun_simple('0.0.0.0',8000,Application({'reader':'synthetic-password'}),use_reloader=False)",
            ],
            readiness={"target": "/", "status": 401},
            controls=[
                {
                    "target": "/",
                    "headers": [
                        {
                            "name": "Authorization",
                            "value": "Basic "
                            + base64.b64encode(b"reader:synthetic-password").decode(),
                        }
                    ],
                    "expected_status": 200,
                    "expected_body_sha256": hashlib.sha256(b"Logged in as reader").hexdigest(),
                }
            ],
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("flask-checkout", "werkzeug-checkout", "wheelhouse", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--docker-socket", type=Path)
    parser.add_argument("--authorize-preparation", action="store_true")
    parser.add_argument("--authorize-execution", action="store_true")
    args = parser.parse_args()
    if args.authorize_execution and not args.authorize_preparation:
        parser.error("Execution demonstration also requires preparation authorization")
    if args.authorize_preparation and args.docker_socket is None:
        parser.error("Preparation requires an explicit Docker Unix socket")
    args.output.mkdir(mode=0o700)
    settings = profiles(args.wheelhouse)
    summary = []
    for name, checkout, component in [
        ("flask", args.flask_checkout, "examples/tutorial"),
        ("werkzeug", args.werkzeug_checkout, "examples"),
    ]:
        if checkout_head(checkout) != PINS[name] or _command(
            checkout, ["status", "--porcelain", "--untracked-files=all", "--", component]
        ):
            raise RunnerFailure(
                "upstream_revision_mismatch", "Use the exact pinned clean upstream example checkout"
            )
        root = args.output / name
        root.mkdir()
        scan = root / "scan"
        prepare_import(
            checkout,
            component,
            b'{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"onboarding example"}},"results":[]}]}',
            scan,
        )
        config = root / "application.json"
        config.write_text(json.dumps(settings[name], indent=2) + "\n")
        plan = root / "onboarding.json"
        plan.write_text(inspect_application(scan, config).model_dump_json(indent=2) + "\n")
        row = {
            "repository": "https://github.com/pallets/" + name,
            "revision": PINS[name],
            "component": component,
            "stage": "planned",
            "vulnerability_assessment": None,
        }
        if args.authorize_preparation:
            prepared = root / "prepared"
            prepare_application(
                scan=scan,
                plan=plan,
                config=config,
                wheelhouse=args.wheelhouse,
                socket=args.docker_socket,
                output=prepared,
                authorize_preparation=True,
            )
            row["stage"] = "prepared"
            if args.authorize_execution:
                result = exercise_application(
                    scan=scan,
                    plan=plan,
                    config=config,
                    preparation=prepared / "prepared-application.json",
                    socket=args.docker_socket,
                    output=root / "exercise",
                    authorize_execution=True,
                )
                row["stage"] = result.outcome
                if result.outcome != "completed":
                    raise RunnerFailure(
                        "example_failed",
                        "Upstream example did not pass; inspect retained exercise evidence",
                    )
        summary.append(row)
    publish(args.output / "summary.json", json.dumps(summary, indent=2) + "\n")
    print(args.output / "summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
