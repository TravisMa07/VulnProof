"""Reviewed CWE-22 driver; execute only in the prepared restricted container."""

import base64
import hashlib
import io
import json
import os
import secrets
from contextlib import redirect_stdout
from importlib import import_module
from pathlib import Path
from threading import Thread
from typing import Any, cast
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

from flask import Flask
from werkzeug.serving import make_server

DOCUMENT_SHA256 = "62527d78c70ef8f47bffc15e6c5352dd6f0a751b97f620013e52c25a138aa62f"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def main() -> None:
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "profile": "fixture-cwe22-validation-v1",
        "outcome": "failed",
        "diagnostics_passed": False,
        "control": None,
        "canary": None,
        "probes": [],
        "errors": [],
    }
    server = None
    thread = None
    try:
        # Reuse the reviewed in-container checks before any traversal probe.
        output = io.StringIO()
        with redirect_stdout(output):
            import_module("diagnostic_driver").main()
        checked = json.loads(output.getvalue())
        if not checked["checks"] or not all(checked["checks"].values()):
            raise RuntimeError("diagnostics_failed")
        report["diagnostics_passed"] = True
        app = cast(Flask, import_module("app").app)
        server = make_server("127.0.0.1", 0, app)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        opener = build_opener(ProxyHandler({}), NoRedirect())

        def request(name: str) -> dict[str, Any]:
            url = f"http://127.0.0.1:{server.server_port}/download?" + urlencode({"name": name})
            try:
                response = opener.open(url, timeout=3)
            except HTTPError as exc:
                response = exc
            with response:
                body = response.read(65537)
                if len(body) > 65536:
                    raise RuntimeError("response_limit")
                if response.code >= 500:
                    raise RuntimeError("server_error")
                return {
                    "status": response.code,
                    "body_base64": base64.b64encode(body).decode("ascii"),
                }

        control = request("example.txt")
        report["control"] = control
        control_body = base64.b64decode(control["body_base64"])
        if control["status"] != 200 or hashlib.sha256(control_body).hexdigest() != DOCUMENT_SHA256:
            raise RuntimeError("control_failed")
        directory = Path("/tmp/vulnproof")
        directory.mkdir(mode=0o700)
        path = directory / (secrets.token_hex(16) + ".txt")
        body = b"VulnProof:" + secrets.token_bytes(32).hex().encode("ascii") + b"\n"
        # Exclusive creation proves initial absence; content is generated after the control.
        with path.open("xb") as stream:
            stream.write(body)
        if path.read_bytes() != body:
            raise RuntimeError("canary_write_failed")
        report["canary"] = {
            "path": str(path),
            "initially_absent": True,
            "body_base64": base64.b64encode(body).decode("ascii"),
        }
        for kind, name in (
            ("parent_traversal", os.path.relpath(path, "/fixture/downloads")),
            ("absolute_path", str(path)),
        ):
            observation = request(name)
            report["probes"].append({"kind": kind, **observation})
        report["outcome"] = "completed"
    except Exception:
        # Preserve earlier observations, including disclosure before a later failure.
        report["errors"].append("driver_operation_failed")
    finally:
        if server is not None:
            try:
                server.shutdown()
                server.server_close()
                if thread is not None:
                    thread.join(timeout=3)
            except Exception:
                report["outcome"] = "failed"
                report["errors"].append("driver_shutdown_failed")
        print(json.dumps(report))


if __name__ == "__main__":
    main()
