import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pytest
from tests.repository_control_support import control_inputs

from vulnproof.planning.repository import Configuration
from vulnproof.runner.control_driver import request_target


def test_fixed_values_survive_control_and_probes(tmp_path: Path) -> None:
    args = control_inputs(tmp_path, mode="fixed_query")
    plan = json.loads(args["plan"].read_bytes())
    assert plan["schema_version"] == "1.1"
    row = plan["findings"][0]
    request = row["http_request"]
    for value in ("manual.txt", "../marker.txt", "/tmp/ü &?.txt"):
        pairs = parse_qsl(urlsplit(request_target(request, value)).query, keep_blank_values=True)
        assert pairs == [("model", "demo & ü"), ("version", ""), ("document", value)]
    assert row["control"]["request_target"] == request_target(request, "manual.txt")


@pytest.mark.parametrize("mode", ["duplicate", "selected", "query", "fragment"])
def test_invalid_requests_rejected(mode: str) -> None:
    request: dict[str, Any] = dict(
        schema_version="1.0",
        route="/export",
        query_key="document",
        control_value="manual.txt",
        fixed_query=[{"name": "model", "value": "x"}],
    )
    if mode == "duplicate":
        request["fixed_query"] *= 2
    elif mode == "selected":
        request["query_key"] = "model"
    else:
        request["route"] += "?x=1" if mode == "query" else "#fragment"
    with pytest.raises(ValueError):
        request_target(request, "manual.txt")


def test_old_configuration_cannot_hide_new_fields(tmp_path: Path) -> None:
    args = control_inputs(tmp_path, mode="fixed_query")
    config = json.loads(args["config"].read_bytes())
    config["schema_version"] = "1.0"
    with pytest.raises(ValueError):
        Configuration.model_validate_json(json.dumps(config))


def test_edited_control_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.test_repository_controls import setup

    from vulnproof.runner.controls import RepositoryControlAttempt, check_repository

    args, _ = setup(tmp_path, monkeypatch)
    attempt = check_repository(**args)
    data = attempt.model_dump(mode="json")
    data["schema_version"] = "1.1"
    data["http_request"] = dict(
        schema_version="1.0",
        route="/export",
        query_key="document",
        control_value="changed.txt",
        fixed_query=[],
    )
    with pytest.raises(ValueError, match="Control request"):
        RepositoryControlAttempt.model_validate_json(json.dumps(data))
    data.pop("http_request")
    data["schema_version"] = "1.0"
    assert RepositoryControlAttempt.model_validate_json(json.dumps(data)) == attempt
