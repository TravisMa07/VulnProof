"""Reviewed synthetic injection benchmark. Execute only in the authorized sandbox."""

import subprocess

from flask import Flask, request

app = Flask(__name__, static_folder=None)


@app.get("/ready")
def ready() -> str:
    return "ready"


@app.get("/test")
def exercise() -> str:
    value = request.args.get("value", "reader")
    return subprocess.check_output(["printf", "%s", value], timeout=2).decode()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False, use_reloader=False)
