"""Fixed HTTP and restriction checks; this file runs only inside fixture images."""

import errno
import fcntl
import os
import socket
import struct
from importlib import import_module
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from typing import cast
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, build_opener

from flask import Flask
from werkzeug.serving import make_server

ROOT = Path("/fixture")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)
    print(f"PASS: {message}", flush=True)


def restrictions() -> None:
    require(os.getuid() != 0, "non-root process")
    status = Path("/proc/self/status").read_text()
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    require(fields["NoNewPrivs"].strip() == "1", "no new privileges")
    require(int(fields["CapEff"].strip(), 16) == 0, "no effective capabilities")
    require(bool(os.statvfs("/").f_flag & os.ST_RDONLY), "read-only root filesystem")
    try:
        (ROOT / "write-probe").write_text("unexpected")
    except OSError as error:
        require(error.errno in (errno.EROFS, errno.EACCES), "root filesystem write denied")
    else:
        raise RuntimeError("root filesystem unexpectedly writable")
    with TemporaryDirectory(dir="/tmp") as directory:
        probe = Path(directory) / "probe"
        probe.write_text("temporary")
        require(probe.read_text() == "temporary", "temporary storage writable")
    # Linux can expose inactive fallback tunnel devices even with --network=none.
    # SIOCGIFFLAGS (0x8913) reads flags in this process's network namespace;
    # IFF_UP (0x1) distinguishes active interfaces from those inert devices.
    active = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        for _, name in socket.if_nameindex():
            request_bytes = struct.pack("256s", name.encode("ascii"))
            response_bytes = fcntl.ioctl(control.fileno(), 0x8913, request_bytes)
            flags = struct.unpack_from("H", response_bytes, 16)[0]
            if flags & 0x1:
                active.add(name)
    require(active == {"lo"}, f"only loopback active (observed {sorted(active)})")


def main() -> None:
    restrictions()
    variant = (ROOT / "variant").read_text()
    require(variant in ("vulnerable", "patched"), "known fixture variant")
    app = cast(Flask, import_module("app").app)
    require(not app.debug and app.static_folder is None, "debugging and static serving disabled")
    server = make_server("127.0.0.1", 0, app)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    opener = build_opener(ProxyHandler({}))
    canary = (ROOT / "canary.txt").read_bytes()
    document = (ROOT / "downloads/example.txt").read_bytes()
    traversal_status = 200 if variant == "vulnerable" else 404
    cases: list[tuple[str, str | None, int, bytes | None]] = [
        ("valid document", "example.txt", 200, document),
        ("parent traversal", "../canary.txt", traversal_status, None),
        ("absolute path", "/fixture/canary.txt", traversal_status, None),
        ("missing name", None, 400, None),
        ("empty name", "", 400, None),
        ("nonexistent file", "does-not-exist.txt", 404, None),
    ]
    try:
        for label, name, expected_status, expected_body in cases:
            query = "" if name is None else "?" + urlencode({"name": name})
            url = f"http://127.0.0.1:{server.server_port}/download{query}"
            try:
                response = opener.open(url, timeout=3)
            except HTTPError as error:
                response = error
            with response:
                body = response.read(65537)
                require(len(body) <= 65536, f"{label}: bounded response")
                require(response.code == expected_status, f"{label}: HTTP {expected_status}")
            if label in ("parent traversal", "absolute path"):
                if variant == "vulnerable":
                    require(body == canary, f"{label}: exact synthetic canary")
                else:
                    require(canary not in body, f"{label}: no canary disclosure")
            elif expected_body is not None:
                require(body == expected_body, f"{label}: exact document")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    main()
