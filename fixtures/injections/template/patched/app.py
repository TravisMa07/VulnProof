"""Reviewed synthetic injection benchmark. Execute only in the authorized sandbox."""

from flask import Flask, render_template_string, request

app = Flask(__name__, static_folder=None)


@app.get("/ready")
def ready() -> str:
    return "ready"


@app.get("/test")
def exercise() -> str:
    value = request.args.get("value", "reader")
    return render_template_string("{{ value }}", value=value)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False, use_reloader=False)
