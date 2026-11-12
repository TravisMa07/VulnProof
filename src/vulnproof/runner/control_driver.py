"""Packaged control observer/server. Run only inside a prepared Linux container."""

import errno
import fcntl
import hashlib
import http.client
import importlib
import json
import os
import re
import secrets
import select
import socket
import struct
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType
from typing import Any
from urllib.parse import quote, urlencode

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


def request_target(profile: dict[str, Any], value: str) -> str:
    """Construct a bounded local GET target; shared by host and packaged observer."""
    if set(profile) != {
        "schema_version",
        "route",
        "query_key",
        "fixed_query",
        "control_value",
    } or profile["schema_version"] not in ("1.0", "1.1"):
        raise ValueError("Invalid GET request profile")
    route, key, fixed = profile["route"], profile["query_key"], profile["fixed_query"]
    path_input = profile["schema_version"] == "1.1"
    if path_input:
        if not isinstance(route, str) or not isinstance(key, str) or not key.isidentifier():
            raise ValueError("Invalid path binding")
        placeholder = "<path:" + key + ">"
        if route.count(placeholder) != 1 or re.search(r"[<>]", route.replace(placeholder, "")):
            raise ValueError("Expected exactly one path converter")
        route = route.replace(placeholder, "placeholder")
    if (
        not isinstance(route, str)
        or not route.startswith("/")
        or route.startswith("//")
        or any(c in route for c in "?#\\<>")
        or not route.isascii()
        or any(ord(c) <= 32 or ord(c) == 127 for c in route)
    ):
        raise ValueError("Expected a literal local route without query or fragment")
    if not isinstance(key, str) or not key or len(key) > 256:
        raise ValueError("Expected one selected query key")
    if not isinstance(value, str) or not isinstance(profile["control_value"], str):
        raise ValueError("Expected string query values")
    if not isinstance(fixed, list) or len(fixed) > 64:
        raise ValueError("Expected at most 64 fixed query parameters")
    pairs = []
    names = set() if path_input else {key}
    for item in fixed:
        if not isinstance(item, dict) or set(item) != {"name", "value"}:
            raise ValueError("Expected fixed name/value pairs")
        name, constant = item["name"], item["value"]
        if not isinstance(name, str) or not name or len(name) > 256 or name in names:
            raise ValueError("Duplicate or conflicting query parameter")
        if not isinstance(constant, str) or len(constant) > 4096:
            raise ValueError("Invalid fixed query value")
        names.add(name)
        pairs.append((name, constant))
    if path_input:
        target = str(profile["route"]).replace("<path:" + key + ">", quote(value, safe="/"))
        if pairs:
            target += "?" + urlencode(pairs)
    else:
        target = route + "?" + urlencode([*pairs, (key, value)])
    if target.startswith("//"):
        raise ValueError("Request target must not resemble an authority")
    if len(target) > 16384:
        raise ValueError("Request target exceeds limit")
    return target


def probe_files(port: int, request: dict[str, Any]) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "outcome": "failed",
        "reason": "boundary_unavailable",
        "canary_path": None,
        "canary_body": None,
        "download_root": None,
        "probes": [],
    }
    try:
        root = Path(request["download_root"]).resolve(strict=True)
        evidence["download_root"] = str(root)
        directory = Path("/tmp/vulnproof")
        if not root.is_dir() or directory.exists() or directory.is_symlink():
            return evidence
        directory.mkdir(mode=0o700)
        if directory.resolve().is_relative_to(root):
            evidence["reason"] = "canary_inside_download_root"
            return evidence
        marker = "VulnProof:" + secrets.token_hex(32) + "\n"
        canary = directory / (secrets.token_hex(16) + ".txt")
        with canary.open("x") as stream:
            stream.write(marker)
        evidence.update(
            canary_path=str(canary),
            canary_body=marker,
            initially_absent=True,
            reason="probe_failed",
        )
        for kind, value in (
            ("parent_traversal", os.path.relpath(canary, root)),
            ("absolute_path", str(canary)),
        ):
            target = (
                request_target(request["http_request"], value)
                if request.get("http_request")
                else request["route"] + "?" + urlencode({request["query_key"]: value})
            )
            observed: dict[str, Any] = {
                "kind": kind,
                "request_target": target,
                "status": None,
                "body_sha256": None,
                "body_bytes": None,
                "truncated": False,
            }
            evidence["probes"].append(observed)
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=REQUEST_TIMEOUT)
            try:
                connection.request("GET", target)
                response = connection.getresponse()
                body = response.read(RESPONSE_LIMIT + 1)
                observed.update(
                    status=response.status,
                    body_bytes=len(body),
                    truncated=len(body) > RESPONSE_LIMIT,
                )
                if len(body) > RESPONSE_LIMIT:
                    evidence["reason"] = "response_limit"
                    return evidence
                observed["body_sha256"] = hashlib.sha256(body).hexdigest()
            finally:
                connection.close()
        evidence.update(outcome="completed", reason="probes_completed")
    except OSError, ValueError, http.client.HTTPException:
        pass
    return evidence


VALIDATION_HANDLERS = MappingProxyType({"cwe22-file-read-v1": probe_files})


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
    handler = VALIDATION_HANDLERS.get(request.get("validator_id", "cwe22-file-read-v1"))
    if request.get("validation"):
        result["validation"] = None
        if handler is None:
            result["reason"] = "unsupported_validator"
            return result
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
            connection.request(
                "GET",
                request_target(request["http_request"], request["http_request"]["control_value"])
                if request.get("http_request")
                else request["request_target"],
            )
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
                if request.get("validation"):
                    assert handler is not None
                    result["validation"] = handler(port, request)
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
