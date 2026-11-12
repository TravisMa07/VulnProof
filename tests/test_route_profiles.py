import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pytest
from tests.repository_control_support import control_inputs

from vulnproof.runner.control_driver import request_target


def profile() -> dict[str, Any]:
    return dict(
        schema_version="1.1",
        route="/download/<path:document>",
        query_key="document",
        control_value="manual.txt",
        fixed_query=[{"name": "v", "value": "ü &?"}],
    )


@pytest.mark.parametrize(
    "value", ["manual.txt", "../marker.txt", "/tmp/marker.txt", "a b/ü?#%.txt"]
)
def test_path_request_is_exact(value: str) -> None:
    from urllib.parse import quote

    target = request_target(profile(), value)
    assert target.startswith("/download/" + quote(value, safe="/"))
    assert parse_qsl(urlsplit(target).query) == [("v", "ü &?")]
    if value.startswith(".."):
        assert "/../" in target


@pytest.mark.parametrize(
    "route",
    [
        "/x/<name>",
        "/x/<int:document>",
        "/x/<path:document>/<path:other>",
        "//host/<path:document>",
        "/x/<path:document>?x=y",
    ],
)
def test_unsupported_templates_rejected(route: str) -> None:
    request = profile() | {"route": route}
    with pytest.raises(ValueError):
        request_target(request, "manual.txt")


def test_discovered_route_binding(tmp_path: Path) -> None:
    args = control_inputs(tmp_path, mode="route")
    plan = json.loads(args["plan"].read_bytes())
    row = plan["findings"][0]
    assert row["status"] == "draft"
    assert row["http_request"]["schema_version"] == "1.1"
    assert row["http_request"]["route"] == "/export/<path:document>"
    assert row["control"]["request_target"].startswith("/export/manual.txt?")
    discovery = json.loads(args["discovery"].read_bytes())
    binding = next(iter(discovery["paths"].values()))["bindings"][0]
    assert binding["inputs"][0]["kind"] == "path"


def test_conflicting_path_declaration_blocks(tmp_path: Path) -> None:
    from vulnproof.planning.repository import plan_repository

    args = control_inputs(tmp_path, mode="route")
    config = json.loads(args["config"].read_bytes())
    config["endpoints"][0]["path_parameter"] = "other"
    args["config"].write_text(json.dumps(config))
    plan = json.loads(
        plan_repository(
            args["scan"],
            args["investigation"],
            args["correlation"],
            args["discovery"],
            args["config"],
        )
    )
    assert plan["findings"][0]["status"] == "blocked"
    assert "configuration_conflict" in plan["findings"][0]["reasons"]
