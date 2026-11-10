from typing import Any

import pytest

from vulnproof.planning.repository import Endpoint, disposition


def plan(
    *routes: str | None,
    status: str = "single_candidate",
    analysis: str = "completed",
    selected: str | None = None,
) -> dict[str, Any]:
    profile = Endpoint(
        file="app.py",
        handler="export",
        route=selected,
        download_root="/data/files",
        control_value="manual.txt",
        control_sha256="a" * 64,
    )
    paths = {}
    for i, route in enumerate(routes):
        paths[str(i)] = {
            "bindings": [
                {
                    "handler": "export",
                    "handler_location": {"path": "app.py"},
                    "application_location": {"path": "app.py"},
                    "application_symbol": "svc",
                    "route_parts": {"route": route, "methods": ["GET"]},
                    "inputs": [{"name": "name"}],
                }
            ],
            "gaps": [],
        }
    row = {
        "finding_id": "occurrence",
        "correlation_status": status,
        "candidates": {"sink": list(paths)},
    }
    return disposition(row, paths, analysis, {("app.py", "export"): profile}, {"app.py"})


@pytest.mark.parametrize(
    ("status", "analysis", "reason"),
    [
        ("ambiguous", "completed", "ambiguous"),
        ("single_candidate", "partial", "analysis_partial"),
        ("no_candidate", "completed", "no_candidate"),
        ("analysis_failed", "failed", "analysis_failed"),
    ],
)
def test_static_gaps_block_drafts(status: str, analysis: str, reason: str) -> None:
    row = plan("/files", status=status, analysis=analysis, selected="/files")
    assert row["status"] == "blocked" and reason in row["reasons"]


def test_selection_retains_alternative_paths_and_provenance() -> None:
    routes = ("/files", "/files", "/other")
    assert plan(*routes)["reasons"] == ["endpoint_selection_required"]
    row = plan(*routes, selected="/files")
    assert row["status"] == "draft"
    assert row["candidates"] == {"sink": ["0", "1", "2"]}
    assert [s["path_id"] for s in row["support"]] == ["0", "1"]
    assert row["support"][0]["origins"]["route"] == "observed"
    conflict = plan(*routes, selected="/unknown")
    assert conflict["reasons"] == ["configuration_conflict"]
    assert conflict["conflicts"][0]["fields"]["route"] == {
        "observed": "/files",
        "declared": "/unknown",
    }


def test_unresolved_alternative_cannot_hide_conflicting_route() -> None:
    assert plan("/export", None, selected="/wrong")["reasons"] == ["configuration_conflict"]
