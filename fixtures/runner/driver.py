"""Trusted diagnostic driver. Execute only inside the prepared fixture image."""

import errno
import fcntl
import hashlib
import json
import os
import socket
import struct
from importlib import import_module
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from typing import cast
from urllib.request import ProxyHandler, build_opener

from flask import Flask
from werkzeug.serving import make_server

DOCUMENT_SHA256 = "62527d78c70ef8f47bffc15e6c5352dd6f0a751b97f620013e52c25a138aa62f"


def main() -> None:
    checks: dict[str, bool] = {}
    checks["non_root"] = os.getuid() == 10001 and os.getgid() == 10001
    fields = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    checks["no_new_privileges"] = fields["NoNewPrivs"].strip() == "1"
    checks["zero_capabilities"] = int(fields["CapEff"].strip(), 16) == 0
    checks["read_only_root"] = bool(os.statvfs("/").f_flag & os.ST_RDONLY)
    try:
        Path("/fixture/write-probe").write_text("unexpected")
    except OSError as exc:
        checks["root_write_denied"] = exc.errno in (errno.EROFS, errno.EACCES)
    else:
        checks["root_write_denied"] = False
    with TemporaryDirectory(dir="/tmp") as directory:
        probe = Path(directory) / "probe"
        probe.write_text("temporary")
        checks["temporary_write"] = probe.read_text() == "temporary"
    active = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        for _, name in socket.if_nameindex():
            flags = fcntl.ioctl(control.fileno(), 0x8913, struct.pack("256s", name.encode("ascii")))
            if struct.unpack_from("H", flags, 16)[0] & 0x1:
                active.add(name)
    checks["only_loopback"] = active == {"lo"}
    if not all(checks.values()):
        raise RuntimeError("Container diagnostics failed before application startup")
    app = cast(Flask, import_module("app").app)
    checks["debug_disabled"] = not app.debug and app.static_folder is None
    if not checks["debug_disabled"]:
        raise RuntimeError("Fixture configuration mismatch")
    server = make_server("127.0.0.1", 0, app)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        opener = build_opener(ProxyHandler({}))
        with opener.open(
            f"http://127.0.0.1:{server.server_port}/download?name=example.txt", timeout=3
        ) as response:
            body = response.read(65537)
            checks["legitimate_download"] = (
                response.code == 200
                and len(body) <= 65536
                and hashlib.sha256(body).hexdigest() == DOCUMENT_SHA256
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    if not all(checks.values()):
        raise RuntimeError("Legitimate download control failed")
    print(
        json.dumps({"schema_version": "1.0", "profile": "fixture-diagnostics-v1", "checks": checks})
    )


if __name__ == "__main__":
    main()
