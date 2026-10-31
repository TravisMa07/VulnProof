"""Framework-based traversal fix for a fixed directory without symlinks or uploads."""

from pathlib import Path

from flask import Flask, Response, abort, request, send_from_directory

app = Flask(__name__, static_folder=None)
DOWNLOAD_ROOT = Path("/fixture/downloads")


@app.get("/download")
def download() -> Response:
    name = request.args.get("name")
    if not name:
        abort(400)
    return send_from_directory(DOWNLOAD_ROOT, name)
