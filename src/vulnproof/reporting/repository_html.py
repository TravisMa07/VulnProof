"""Passive repository inventory, modeled flows, and separate runtime observations."""

import base64
import hashlib
import json
from collections import Counter
from typing import Any

from .html import CSS, table
from .markup import text
from .repository import RepositoryReport, ValidationDetail


def details(title: str, value: object) -> str:
    return (
        "<details><summary>"
        + text(title)
        + "</summary><pre>"
        + text(json.dumps(value, indent=2, ensure_ascii=False))
        + "</pre></details>"
    )


def flow(steps: list[tuple[str, object]]) -> str:
    return (
        '<ol class="flow">'
        + "".join(
            '<li><div class="flow-node"><strong>'
            + text(title)
            + "</strong><p>"
            + text(value)
            + "</p></div></li>"
            for title, value in steps
        )
        + "</ol>"
    )


def marker_comparison(observed: dict[str, Any], probe: dict[str, Any]) -> str:
    marker = observed.get("canary_body")
    if not isinstance(marker, str):
        return "expected marker unavailable"
    matches = (
        probe.get("status") == 200
        and probe.get("truncated") is False
        and probe.get("body_sha256") == hashlib.sha256(marker.encode()).hexdigest()
        and probe.get("body_bytes") == len(marker.encode())
    )
    return "exact marker response: " + ("observed" if matches else "not observed")


def runtime(detail: ValidationDetail) -> str:
    result = detail.result
    sections = ["<section class='record'><h4>" + text(detail.label) + "</h4>"]
    if detail.warnings:
        sections.append(
            '<p class="notice">Evidence integrity warning: '
            + text(" ".join(detail.warnings))
            + "</p>"
        )
    if result is None:
        return "".join(sections) + "<p>No readable result.</p></section>"
    sections.append(
        "<p><strong>Recorded classification: "
        + text(result.classification)
        + "</strong> · "
        + text(result.reason.replace("_", " "))
        + "</p>"
    )
    attempt = result.attempt
    if attempt is None:
        sections.append("<p>No runtime attempt was retained. See the planning reasons.</p>")
    else:
        if attempt.http_request is not None:
            sections.append(
                "<p>Varied "
                + ("path" if attempt.http_request["schema_version"] == "1.1" else "query")
                + " parameter: <strong>"
                + text(attempt.http_request["query_key"])
                + "</strong>. Fixed parameters are preserved in every request.</p>"
            )
            sections.append(details("Structured GET request", attempt.http_request))
        driver = attempt.driver
        steps: list[tuple[str, object]] = [
            (
                "Container admission",
                "Requested restrictions verified: " + str(attempt.policy_verified),
            ),
            ("Legitimate request", attempt.request.get("request_target", "not recorded")),
            (
                "Control response",
                f"{driver.control}: HTTP {driver.status}" if driver else "No parsed observation",
            ),
        ]
        observed = driver.validation if driver else None
        if observed:
            steps.append(("File boundary", observed.get("download_root", "not recorded")))
            steps.append(("Synthetic marker", observed.get("canary_path", "not recorded")))
            probes = observed.get("probes", [])
            if isinstance(probes, list):
                for probe in probes:
                    if isinstance(probe, dict):
                        steps.append(
                            (
                                str(probe.get("kind", "probe")),
                                f"{probe.get('request_target')} → HTTP {probe.get('status')}; "
                                f"{probe.get('body_bytes')} bytes; truncated: {probe.get('truncated')}; "
                                + marker_comparison(observed, probe),
                            )
                        )
            steps.append(("Probe outcome", observed.get("reason", "not recorded")))
        else:
            steps.append(("Bounded probes", "No probe observations retained"))
        steps.extend([("Execution", attempt.execution), ("Cleanup", attempt.cleanup)])
        sections.append(flow(steps))
        if driver:
            expected = attempt.request.get("body_sha256")
            sections.append(
                "<details><summary>Control response comparison</summary>"
                + table(
                    ("Control comparison", "Value"),
                    (
                        ("Expected body SHA-256", expected),
                        ("Observed body SHA-256", driver.body_sha256),
                        ("Observed body bytes", driver.body_bytes),
                        ("Response truncated", driver.truncated),
                    ),
                )
                + "</details>"
            )
        sections.append(
            details(
                "Inspect runtime policy, requests, digests, and observations",
                attempt.model_dump(mode="json"),
            )
        )
    sections.append(details("Inspect original result", result.model_dump(mode="json")))
    sections.append("</section>")
    return "".join(sections)


def render_repository_html(report: RepositoryReport) -> str:
    style_hash = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    policy = (
        f"default-src 'none'; style-src 'sha256-{style_hash}'; base-uri 'none'; form-action 'none'"
    )
    rows = report.plan["findings"]
    known_ids = {r["finding_id"] for r in rows}
    by_id: dict[str, list[ValidationDetail]] = {}
    for detail in report.validations:
        if detail.result:
            by_id.setdefault(detail.result.finding_id, []).append(detail)
    counts = Counter(d.result.classification for d in report.validations if d.result)
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="' + text(policy) + '">',
        "<title>VulnProof repository evidence</title><style>" + CSS + "</style></head><body><main>",
        "<header><h1>Repository evidence report</h1><p>Offline investigation · every retained occurrence · separate attempts</p>",
        '<p class="notice">Evidence integrity: <strong>' + text(report.integrity) + "</strong>. "
        "Recorded classifications are historical claims. Integrity checks compare local evidence; they do not authenticate its producer.</p>",
        "<p>Scope: " + text(report.plan.get("component") or "whole captured checkout") + "</p>",
        "<p>Scanner/source association: "
        + text(report.plan.get("scanner_source_state"))
        + "</p></header>",
    ]
    parts.extend('<p class="notice">' + text(w) + "</p>" for w in report.warnings)
    parts.append(
        "<h2>Investigation overview</h2>"
        + flow(
            [
                (
                    "Scanner findings",
                    "Semgrep scan or imported SARIF → retained occurrence inventory",
                ),
                ("Captured source", "Source fingerprint and scanner revision association"),
                ("CodeQL investigation", report.plan.get("analysis_outcome")),
                (
                    "Correlation and request discovery",
                    "Compatible sink results → modeled paths → handler and request bindings",
                ),
                (
                    "Validation plans",
                    "Observed bindings and operator declarations → draft or blocked",
                ),
                (
                    "Authorized container tests",
                    "Fresh legitimate control → bounded probes → cleanup, when attempts are supplied",
                ),
                (
                    "Recorded assessments",
                    "Each attempt retains its own classification and limitations",
                ),
            ]
        )
    )
    parts.append(
        table(
            ("Summary", "Count"),
            [
                ("SARIF occurrences", len(rows)),
                (
                    "Occurrences with no supplied result",
                    sum(r["finding_id"] not in by_id for r in rows),
                ),
                ("Supplied validation directories", len(report.validations)),
                *(
                    ("Attempts: " + name, counts[name])
                    for name in ("confirmed", "inconclusive", "unsupported", "failed")
                ),
            ],
        )
    )
    parts.append(
        "<p>Counts of classifications refer to attempts, not unique findings. No supplied result means not tested in this report, not safe. An unsuccessful probe never establishes safety.</p>"
    )
    parts.append("<h2>Finding inventory</h2><ul>")
    for index, row in enumerate(rows):
        attempts = by_id.get(row["finding_id"], [])
        summary = (
            ", ".join(d.result.classification for d in attempts if d.result)
            or "not tested in this report"
        )
        parts.append(
            f'<li><a href="#finding-{index}">'
            + f"Finding {index + 1}"
            + "</a> · "
            + text(row.get("status"))
            + " · "
            + text(summary)
            + "</li>"
        )
    parts.append("</ul>")
    links = (
        {
            r["finding"]["id"]: r
            for r in report.correlation.get("findings", [])
            if isinstance(r, dict) and isinstance(r.get("finding"), dict) and "id" in r["finding"]
        }
        if report.correlation
        else {}
    )
    paths = (
        {p.path.id: p.path for r in report.investigation.results for p in r.paths}
        if report.investigation
        else {}
    )
    for index, row in enumerate(rows):
        identity = row["finding_id"]
        parts.append(
            f'<section class="record" id="finding-{index}"><h2>Finding {index + 1}</h2><p>'
            + "Retained occurrence; original identifiers appear in technical details."
            + "</p>"
        )
        parts.append('<p class="story">' + text(story(row, by_id.get(identity, []))) + "</p>")
        scanner = links.get(identity)
        if scanner:
            parts.append(
                details("Scanner message, rule, location, and original occurrence", scanner)
            )
        parts.append(
            flow(
                [
                    ("CodeQL correlation", row.get("correlation_status")),
                    (
                        "Request binding",
                        f"{row.get('method', 'unresolved')} {row.get('route', 'unresolved')} · selected input: {row.get('query_key', 'unresolved')}",
                    ),
                    ("Planning", row.get("status")),
                    (
                        "Remaining gaps",
                        ", ".join(row.get("reasons", []))
                        or "No planning gaps recorded; execution still requires authorization",
                    ),
                ]
            )
        )
        parts.append(
            '<div class="flow-grid"><section><h3>Modeled static flow</h3><p>These are CodeQL locations, not a runtime instruction trace.</p>'
        )
        candidates = row.get("candidates", {})
        supported = {s["path_id"] for s in row.get("support", [])}
        if not candidates:
            parts.append("<p>No compatible modeled path recorded.</p>")
        path_number = 0
        for result_id, ids in candidates.items():
            for pid in ids:
                path_number += 1
                parts.append(
                    "<h4>"
                    + f"Path {path_number}"
                    + (" · supports request" if pid in supported else " · candidate")
                    + "</h4>"
                )
                path = paths.get(pid)
                if path:
                    parts.append(
                        flow(
                            [
                                (
                                    f"Step {i}",
                                    f"{loc.path}:{loc.start_line}"
                                    + (f":{loc.start_column}" if loc.start_column else ""),
                                )
                                for i, loc in enumerate(path.locations, 1)
                            ]
                        )
                    )
                else:
                    parts.append("<p>Path details unavailable.</p>")
                if path:
                    for loc in path.locations:
                        excerpt = report.excerpts.get(f"{loc.path}:{loc.start_line}")
                        if excerpt:
                            parts.append(
                                "<details><summary>Source at "
                                + text(f"{loc.path}:{loc.start_line}")
                                + "</summary><pre>"
                                + text(excerpt)
                                + "</pre></details>"
                            )
                parts.append(details("Path identity", {"path_id": pid, "result_id": result_id}))
        parts.append(
            '</section><section class="runtime-flow"><h3>Observed container behavior</h3><p>Endpoint observations do not prove execution of every modeled node.</p>'
        )
        attempts = by_id.get(identity, [])
        if not attempts:
            parts.append("<p>No validation result supplied for this occurrence.</p>")
        for attempt in attempts:
            parts.append(runtime(attempt))
        parts.append("</section></div>")
        parts.append(
            details("Plan, operator declarations, binding origins, and prerequisites", row)
        )
        parts.append("</section>")
    unmatched = [
        d for d in report.validations if d.result is None or d.result.finding_id not in known_ids
    ]
    if unmatched:
        parts.append("<h2>Unassociated or unreadable validation evidence</h2>")
        parts.extend(runtime(d) for d in unmatched)
    parts.append("<h2>Artifacts and diagnostic previews</h2>")
    for artifact in (*report.artifacts, *(a for d in report.validations for a in d.artifacts)):
        parts.append(
            details(
                artifact.artifact.path + " · " + artifact.status, artifact.model_dump(mode="json")
            )
        )
    parts.append(
        details(
            "Report provenance and upstream plan",
            {
                "schema_version": report.schema_version,
                "profile": report.profile,
                "plan_sha256": report.plan_sha256,
                "plan": report.plan,
            },
        )
    )
    parts.append(
        "<p>Application and observer share a container and UID. Runtime records are not attestations against hostile application code. Missing, changed, or truncated evidence limits interpretation.</p></main></body></html>"
    )
    return "".join(parts)


def story(row: dict[str, Any], attempts: list[ValidationDetail]) -> str:
    if row.get("status") != "draft":
        return (
            "Planning stopped: "
            + ", ".join(str(r).replace("_", " ") for r in row.get("reasons", []))
            + ". Inspect the gaps below."
        )
    if not attempts:
        return "A request was planned from the retained evidence. No validation result was supplied, so this report contains no runtime conclusion for this finding."
    return (
        "The planned request has "
        + str(len(attempts))
        + " retained validation result(s). Inspect each control, probe, and cleanup outcome below; attempts are not combined into a new verdict."
    )
