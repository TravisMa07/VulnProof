"""Synthetic application onboarding cases; no vulnerability claims."""

import hashlib
import json
from pathlib import Path
from typing import Any

from vulnproof.correlation.repository import prepare_import
from vulnproof.onboarding.planning import inspect_application

APP = """import os, sqlite3, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path)
        body = b"ready\\n"
        if path.path == '/count':
            db = sqlite3.connect(os.environ['VULNPROOF_STATE_DIR'] + '/state.db')
            db.execute('update counter set value=value+1')
            db.commit()
            body = str(db.execute('select value from counter').fetchone()[0]).encode()
            db.close()
        elif path.path == '/seed':
            body = open(os.environ['VULNPROOF_STATE_DIR'] + '/seed.txt','rb').read()
        elif path.path == '/fetch':
            body = urllib.request.urlopen(parse_qs(path.query)['url'][0], timeout=2).read()
        elif path.path == '/policy':
            try:
                open('/application/forbidden','w').write('no')
                body = b'unexpected-write'
            except OSError:
                body = ('readonly;uid=' + str(os.getuid())).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        self.send_response(201 if self.headers.get('X-Test') == 'synthetic' else 400)
        self.end_headers()
        self.wfile.write(body)
HTTPServer(('0.0.0.0',8000), Handler).serve_forever()
"""


def inputs(root: Path, mode: str = "http") -> dict[str, Any]:
    repo = root / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(APP)
    (repo / "README.md").write_text("Example application; python app.py")
    (repo / "pyproject.toml").write_text('[project]\nname="synthetic-onboarding"\n')
    scan = root / "scan"
    prepare_import(
        repo,
        None,
        b'{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"test"}},"results":[]}]}',
        scan,
    )

    def control(target: str, body: bytes) -> dict[str, Any]:
        return {
            "target": target,
            "expected_status": 200,
            "expected_body_sha256": hashlib.sha256(body).hexdigest(),
        }

    configuration: dict[str, Any] = dict(
        schema_version="1.0",
        kind="http",
        command=["python", "app.py"],
        seeds=[{"path": "seed.txt", "text": "synthetic\n"}],
        initialize=[
            [
                "python",
                "-c",
                "import sqlite3; d=sqlite3.connect('/tmp/vulnproof-state/state.db'); d.execute('create table counter(value integer)'); d.execute('insert into counter values(0)'); d.commit()",
            ]
        ],
        controls=[
            control("/count", b"1"),
            control("/seed", b"synthetic\n"),
            control("/policy", b"readonly;uid=10001"),
            control("/fetch?url=${TEST_SERVICE_URL}", b"VulnProof isolated test service\n"),
            dict(
                method="POST",
                target="/echo",
                headers=[
                    {"name": "Content-Type", "value": "application/json"},
                    {"name": "X-Test", "value": "synthetic"},
                ],
                body='{"test":true}',
                expected_status=201,
                expected_body_sha256=hashlib.sha256(b'{"test":true}').hexdigest(),
            ),
        ],
    )
    if mode == "harness":
        configuration.update(
            kind="harness",
            command=[
                "python",
                "-c",
                "import pathlib; assert pathlib.Path('/tmp/vulnproof-state/seed.txt').read_text() == 'synthetic\\n'; print('harness completed')",
            ],
            controls=[],
        )
    if mode == "failed_initialize":
        configuration["initialize"] = [["python", "-c", "raise SystemExit(7)"]]
        configuration["readiness"] = {"timeout_seconds": 1}
    if mode == "flood":
        configuration["command"] = ["python", "-c", "print('x'*100000)"]
        configuration["readiness"] = {"timeout_seconds": 1}
    config = root / "app.json"
    config.write_text(json.dumps(configuration))
    plan = root / "onboarding.json"
    plan.write_text(inspect_application(scan, config).model_dump_json(indent=2))
    return dict(scan=scan, config=config, plan=plan)
