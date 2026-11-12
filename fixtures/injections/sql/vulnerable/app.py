"""Reviewed synthetic injection benchmark. Execute only in the authorized sandbox."""

import os
import sqlite3

from flask import Flask, request

app = Flask(__name__, static_folder=None)


@app.get("/ready")
def ready() -> str:
    return "ready"


@app.get("/test")
def exercise() -> str:
    value = request.args.get("value", "reader")
    with sqlite3.connect(os.environ["VULNPROOF_STATE_DIR"] + "/data.db") as db:
        rows = db.execute("SELECT value FROM records WHERE name = '" + value + "'").fetchall()
    return "\n".join(row[0] for row in rows)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False, use_reloader=False)
