"""Installed stdlib-only worker. Application code runs only in its own container."""

import base64
import hashlib
import http.client
import json
import os
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.parse import urlencode

STATE = Path("/tmp/vulnproof-state")
STATUS = Path("/tmp/vulnproof-status.json")
LOG_LIMIT = 16384
log_remaining = LOG_LIMIT
BODY_LIMIT = 65536


def write_status(data: dict[str, Any]) -> None:
    temporary = STATUS.with_suffix(".tmp")
    temporary.write_text(json.dumps(data))
    temporary.replace(STATUS)


def execute(
    command: list[str],
    environment: dict[str, str],
    deadline: float,
    stage: str = "application",
    history: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    global log_remaining
    observed: dict[str, Any] = {
        "outcome": "failed",
        "exit_code": None,
        "log_base64": "",
        "truncated": False,
    }
    process = None
    output = bytearray()
    try:
        process = subprocess.Popen(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        assert process.stdout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    observed["outcome"] = "timed_out"
                    break
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    available = log_remaining
                    output.extend(chunk[:available])
                    log_remaining -= min(len(chunk), available)
                    write_status(
                        {
                            "stage": stage,
                            "outcome": "running",
                            "initialization": history or [],
                            "log_base64": base64.b64encode(output).decode(),
                            "truncated": len(chunk) > available,
                        }
                    )
                    if len(chunk) > available:
                        observed.update(outcome="output_limit", truncated=True)
                        break
                if observed["truncated"]:
                    break
        if observed["outcome"] not in ("timed_out", "output_limit"):
            remaining = max(0.01, deadline - time.monotonic())
            observed["exit_code"] = process.wait(timeout=remaining)
            observed["outcome"] = "completed" if process.returncode == 0 else "failed"
    except subprocess.TimeoutExpired:
        observed["outcome"] = "timed_out"
    except OSError:
        pass
    finally:
        if process:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
        observed["log_base64"] = base64.b64encode(output).decode()
    return observed


def application(config: dict[str, Any]) -> dict[str, Any]:
    deadline = time.monotonic() + 60
    STATE.mkdir(mode=0o700)
    for seed in config["seeds"]:
        target = STATE / seed["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(seed["text"])
    environment = {
        "PATH": os.defpath + ":/usr/local/bin",
        "HOME": str(STATE),
        "TMPDIR": "/tmp",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        **config["environment"],
    }
    environment["VULNPROOF_STATE_DIR"] = str(STATE)
    if config.get("validation_nonce"):
        environment["VULNPROOF_VALIDATION_MARKER"] = "VP_" + config["validation_nonce"]
    history: list[dict[str, Any]] = []
    for command in config["initialize"]:
        write_status({"stage": "initialize", "outcome": "running", "initialization": history})
        step = execute(
            command, environment, min(deadline, time.monotonic() + 15), "initialize", history
        )
        history.append(step)
        if step["outcome"] != "completed":
            status = {"stage": "initialize", **step, "initialization": history}
            write_status(status)
            return status
    write_status({"stage": "application", "outcome": "running"})
    result = execute(config["command"], environment, deadline, config["kind"], history)
    status = {
        "stage": "application" if config["kind"] == "http" else "harness",
        **result,
        "initialization": history,
    }
    write_status(status)
    return status


def runtime_checks() -> dict[str, bool]:
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    checks = {
        "non_root": os.getuid() == 10001 and os.geteuid() == 10001,
        "zero_capabilities": int(status["CapEff"].strip(), 16) == 0,
        "no_new_privileges": status["NoNewPrivs"].strip() == "1",
        "readonly_root": bool(os.statvfs("/").f_flag & os.ST_RDONLY),
    }
    with TemporaryDirectory(dir="/tmp") as directory:
        file = Path(directory) / "probe"
        file.write_text("synthetic")
        checks["temporary_write"] = file.read_text() == "synthetic"
    routes = [line.split() for line in Path("/proc/net/route").read_text().splitlines()[1:]]
    checks["no_default_ipv4_route"] = not any(
        len(row) > 3 and row[1] == "00000000" and int(row[3], 16) & 1 for row in routes
    )
    return checks


def injection_probes(capability: str, value: str, nonce: str) -> list[dict[str, str]]:
    """Fixed bounded templates; request text never contains its complete expected marker."""
    marker = "VP_" + nonce
    left, right = marker[:19], marker[19:]
    if capability == "command":
        return [
            {
                "role": "probe",
                "value": value + "; printf %s '" + left + "'" + "'" + right + "'",
                "marker": marker,
            }
        ]
    if capability == "template":
        return [
            {"role": "probe", "value": "{{ '" + left + "' ~ '" + right + "' }}", "marker": marker}
        ]
    if capability == "sql":
        return [
            {"role": "negative", "value": value + "' AND '1'='2' -- ", "marker": marker},
            {"role": "probe", "value": value + "' OR '1'='1' -- ", "marker": marker},
        ]
    raise ValueError("Unknown installed injection validator")


def injection_target(profile: dict[str, Any], value: str) -> str:
    """GET/query-only representation checked before dispatch by GetRequest."""
    pairs = [(p["name"], p["value"]) for p in profile["fixed_query"]]
    pairs.append((profile["query_key"], value))
    target = str(profile["route"]) + "?" + urlencode(pairs)
    if len(target) > 16384:
        raise ValueError("Request target exceeds limit")
    return target


def observer(config: dict[str, Any], app: str, nonce: str) -> dict[str, Any]:
    callbacks: list[dict[str, Any]] = []
    lock = threading.Lock()
    expected_path = "/callback/" + nonce

    class Service(BaseHTTPRequestHandler):
        def handle_request(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if self.path != expected_path or not 0 <= length <= BODY_LIMIT:
                self.send_error(404)
                return
            self.connection.settimeout(2)
            body = self.rfile.read(length)
            with lock:
                if len(callbacks) >= 32:
                    self.send_error(429)
                    return
                callbacks.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "body_bytes": len(body),
                        "body_sha256": hashlib.sha256(body).hexdigest(),
                    }
                )
            payload = b"VulnProof isolated test service\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = handle_request
        do_POST = handle_request

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("0.0.0.0", 9001), Service)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    result: dict[str, Any] = {
        "outcome": "failed",
        "reason": "not_ready",
        "ready": False,
        "controls": [],
        "callbacks": [],
        "egress_probe_connected": False,
        "runtime_checks": runtime_checks(),
        "validation": None,
    }
    if not all(result["runtime_checks"].values()):
        result["reason"] = "observer_restriction_check_failed"
        server.shutdown()
        server.server_close()
        return result
    total = 0
    deadline = time.monotonic() + 45
    service_url = "http://" + socket.gethostbyname(socket.gethostname()) + ":9001" + expected_path
    # Reachability check uses a documentation-only address and is bounded.
    try:
        with socket.create_connection(("203.0.113.1", 9), timeout=0.5):
            result.update(reason="unexpected_egress_connection", egress_probe_connected=True)
            server.shutdown()
            server.server_close()
            return result
    except OSError:
        result["egress_probe_connected"] = False

    def request(
        method: str,
        target: str,
        headers: dict[str, str],
        body: str | None,
        marker: bytes | None = None,
    ) -> dict[str, Any]:
        nonlocal total
        if time.monotonic() >= deadline:
            raise TimeoutError
        target = target.replace("${TEST_SERVICE_URL}", service_url)
        payload = (
            body.replace("${TEST_SERVICE_URL}", service_url).encode() if body is not None else None
        )
        connection = http.client.HTTPConnection(
            app, config["port"], timeout=min(3, max(0.1, deadline - time.monotonic()))
        )
        try:
            connection.request(method, target, body=payload, headers=headers)
            response = connection.getresponse()
            data = response.read(BODY_LIMIT + 1)
            total += len(data)
            if len(data) > BODY_LIMIT or total > 1024 * 1024:
                raise ValueError("response_limit")
            return {
                "method": method,
                "target": target,
                "request_body_bytes": len(payload or b""),
                "request_body_sha256": hashlib.sha256(payload or b"").hexdigest(),
                "request_headers_sha256": hashlib.sha256(
                    json.dumps(headers, sort_keys=True).encode()
                ).hexdigest(),
                "status": response.status,
                "body_bytes": len(data),
                "body_sha256": hashlib.sha256(data).hexdigest(),
                "truncated": False,
                **({"marker_present": marker in data} if marker is not None else {}),
            }
        finally:
            connection.close()

    try:
        ready_deadline = time.monotonic() + config["readiness"]["timeout_seconds"]
        while time.monotonic() < ready_deadline:
            try:
                response = request("GET", config["readiness"]["target"], {}, None)
                if response["status"] == config["readiness"]["status"]:
                    result["ready"] = True
                    break
            except OSError, http.client.HTTPException:
                pass
            time.sleep(0.1)
        if not result["ready"]:
            return result
        for step in config["controls"]:
            observed = request(
                step["method"],
                step["target"],
                {h["name"]: h["value"] for h in step["headers"]},
                step["body"],
            )
            observed["matched"] = (
                observed["status"] == step["expected_status"]
                and observed["body_sha256"] == step["expected_body_sha256"]
            )
            result["controls"].append(observed)
            if not observed["matched"]:
                result["reason"] = "control_mismatch"
                return result
        validation = config.get("validation")
        if validation:
            marker = ("VP_" + nonce).encode()
            profile = validation["request"]
            control = request(
                "GET", injection_target(profile, profile["control_value"]), {}, None, marker
            )
            matched = (
                control["status"] == 200
                and control["body_sha256"] == validation["control_sha256"]
                and not control["marker_present"]
            )
            attempts: list[dict[str, Any]] = []
            result["validation"] = {
                "capability": validation["capability"],
                "nonce": nonce,
                "control": control,
                "control_valid": matched,
                "attempts": attempts,
            }
            if not matched:
                result["reason"] = "validation_control_failed"
                return result
            for probe in injection_probes(
                validation["capability"], profile["control_value"], nonce
            ):
                observed = request(
                    "GET", injection_target(profile, probe["value"]), {}, None, marker
                )
                attempts.append({"role": probe["role"], **observed})
                if probe["role"] == "negative" and (
                    observed["status"] != 200
                    or observed["marker_present"]
                    or observed["body_sha256"] != hashlib.sha256(b"").hexdigest()
                ):
                    result["reason"] = "sql_negative_control_failed"
                    return result
        result.update(outcome="completed", reason="controls_passed")
    except (OSError, ValueError, http.client.HTTPException) as exc:
        result["reason"] = "response_limit" if str(exc) == "response_limit" else "request_failed"
    finally:
        server.shutdown()
        server.server_close()
        with lock:
            result["callbacks"] = list(callbacks)
    return result


def main() -> None:
    role, raw = sys.argv[1:3]
    config = json.loads(raw)
    if role == "application":
        try:
            result = application(config)
        except BaseException:
            result = {"stage": "initialize", "outcome": "failed", "reason": "initialization_failed"}
            write_status(result)
        if config["kind"] == "harness":
            print(json.dumps(result))
            raise SystemExit(0 if result["outcome"] == "completed" else 1)
        # Keep the namespace alive for bounded host retrieval; owned cleanup removes it.
        while True:
            time.sleep(1)
    elif role == "observer":
        print(json.dumps(observer(config, sys.argv[3], sys.argv[4])))
    elif role == "status":
        print(STATUS.read_text() if STATUS.exists() else '{"outcome":"starting"}')
    else:
        raise ValueError("Unknown installed worker role")


if __name__ == "__main__":
    main()
