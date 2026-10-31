"""Intentionally vulnerable: execute only inside the reviewed fixture container."""

import os
from pathlib import Path

from flask import Flask, Response, abort, request

app = Flask(__name__, static_folder=None)
DOWNLOAD_ROOT = Path("/fixture/downloads")


@app.get("/download")
def download() -> Response:
    name = request.args.get("name")
    if not name:
        abort(400)
    path = os.path.join(DOWNLOAD_ROOT, name)
    try:
        with open(path, "rb") as document:
            return Response(document.read(), mimetype="application/octet-stream")
    except FileNotFoundError:
        abort(404)
