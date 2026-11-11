"""Packaged control observer/server. Run only inside a prepared Linux container."""

import errno
import fcntl
import hashlib
import http.client
import importlib
import json
import os
import select
import socket
import struct
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

CHECKS = (
    "non_root",
    "no_new_privileges",
    "zero_capabilities",
    "read_only_root",
    "root_write_denied",
    "temporary_write",
    "only_loopback",
)
RESPONSE_LIMIT = 65536
STARTUP_TIMEOUT = 10
REQUEST_TIMEOUT = 3


def restrictions() -> dict[str, bool]:
    fields = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    checks = {
        "non_root": os.getuid() == 10001 and os.getgid() == 10001,
        "no_new_privileges": fields["NoNewPrivs"].strip() == "1",
        "zero_capabilities": int(fields["CapEff"].strip(), 16) == 0,
        "read_only_root": bool(os.statvfs("/").f_flag & os.ST_RDONLY),
    }
    active = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        for _, name in socket.if_nameindex():
            flags = fcntl.ioctl(control.fileno(), 0x8913, struct.pack("256s", name.encode("ascii")))
            if struct.unpack_from("H", flags, 16)[0] & 0x1:
                active.add(name)
    checks["only_loopback"] = active == {"lo"}
    try:
        Path("/application/.vulnproof-write-check").write_bytes(b"unexpected")
    except OSError as exc:
        checks["root_write_denied"] = exc.errno in (errno.EROFS, errno.EACCES)
    else:
        checks["root_write_denied"] = False
    with TemporaryDirectory(dir="/tmp") as temporary:
        target = Path(temporary) / "control"
        target.write_bytes(b"temporary")
        checks["temporary_write"] = target.read_bytes() == b"temporary"
    return checks


def serve(entry_point: str, ready_fd: int) -> None:
    # Application output never shares the observer's structured stdout channel.
    sys.stdout = sys.stderr
    reason = "dependency_missing"
    try:
        from flask import Flask
        from werkzeug.serving import make_server

        file, symbol = entry_point.split(":", 1)
        parts = Path(file).with_suffix("").parts
        if not all(part.isidentifier() for part in parts):
            raise ValueError("Unsupported module path")
        module = ".".join(parts[:-1] if parts[-1] == "__init__" else parts)
        sys.path.insert(0, "/application")
        reason = "application_import_failed"
        loaded = importlib.import_module(module)
        reason = "application_symbol_missing"
        application = getattr(loaded, symbol)
        reason = "unsupported_application"
        if not isinstance(application, Flask):
            raise ValueError("Expected a Flask application object, not a factory")
        reason = "debug_enabled"
        if application.debug:
            raise ValueError("Disable debug mode before capture")
        reason = "server_start_failed"
        server = make_server("127.0.0.1", 0, application)
    except BaseException as exc:
        if isinstance(exc, ModuleNotFoundError):
            reason = "dependency_missing"
        os.write(ready_fd, json.dumps({"reason": reason}).encode())
        os.close(ready_fd)
        return
    os.write(ready_fd, json.dumps({"port": server.server_port}).encode())
    os.close(ready_fd)
    server.serve_forever()


def observe(request: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "profile": "repository-control-v1",
        "checks": {},
        "application_started": False,
        "control": "not_run",
        "reason": "restriction_check_failed",
        "status": None,
        "body_sha256": None,
        "body_bytes": None,
        "truncated": False,
    }
    try:
        result["checks"] = restrictions()
        if not all(result["checks"].values()):
            return result
    except OSError, ValueError, KeyError:
        return result
    read_fd, write_fd = os.pipe()
    child: subprocess.Popen[bytes] | None = None
    try:
        child = subprocess.Popen(
            [sys.executable, "-I", __file__, "--serve", request["entry_point"], str(write_fd)],
            stdin=subprocess.DEVNULL,
            stdout=sys.stderr,
            stderr=sys.stderr,
            pass_fds=(write_fd,),
        )
        os.close(write_fd)
        write_fd = -1
        result["reason"] = "startup_timeout"
        if not select.select([read_fd], [], [], STARTUP_TIMEOUT)[0]:
            return result
        ready = json.loads(os.read(read_fd, 4096))
        if "port" not in ready:
            result["reason"] = ready.get("reason", "server_start_failed")
            return result
        port = ready["port"]
        if type(port) is not int or not 0 < port < 65536:
            raise ValueError("Invalid loopback port")
        result["application_started"] = True
        result["control"] = "failed"
        result["reason"] = "request_failed"
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=REQUEST_TIMEOUT)
        try:
            connection.request("GET", request["request_target"])
            response = connection.getresponse()
            body = response.read(RESPONSE_LIMIT + 1)
            result.update(
                status=response.status, body_bytes=len(body), truncated=len(body) > RESPONSE_LIMIT
            )
            if result["truncated"]:
                result["reason"] = "response_limit"
                return result
            result["body_sha256"] = hashlib.sha256(body).hexdigest()
            if response.status != 200:
                result["reason"] = "status_mismatch"
            elif result["body_sha256"] != request["body_sha256"]:
                result["reason"] = "body_mismatch"
            else:
                result.update(control="passed", reason="control_matched")
        finally:
            connection.close()
    except OSError, ValueError, http.client.HTTPException:
        if result["application_started"]:
            result["reason"] = "request_failed"
        else:
            result["reason"] = "server_start_failed"
    finally:
        os.close(read_fd)
        if write_fd != -1:
            os.close(write_fd)
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)
    return result


def main() -> None:
    if len(sys.argv) == 4 and sys.argv[1] == "--serve":
        serve(sys.argv[2], int(sys.argv[3]))
        return
    if len(sys.argv) != 2 or len(sys.argv[1]) > 32768:
        raise ValueError("Expected one bounded control document")
    request = json.loads(sys.argv[1])
    print(json.dumps(observe(request)), flush=True)


if __name__ == "__main__":
    main()
