"""Rebuild plans, check retained attempt transcripts, and render escaped offline reports."""

import json
from html import escape
from pathlib import Path
from typing import Any

from vulnproof.artifacts import read_local
from vulnproof.onboarding.planning import read
from vulnproof.runner.engine import publish

from .integrity import verify_attempt
from .models import Plans
from .planning import LIMIT, digest, plan_injections, verified_investigation
from .runtime import Result, decision


def verify_result(directory: Path, selected: Plans, plan_raw: bytes) -> Result:
    result = Result.model_validate_json(read(directory / "result.json", LIMIT))
    entry = next((e for e in selected.entries if e.finding_id == result.finding_id), None)
    if (
        entry != result.entry
        or result.plans_sha256 != digest(plan_raw)
        or result.source_fingerprint != selected.source_fingerprint
        or result.scanner_source_state != selected.scanner_source_state
    ):
        raise ValueError("Validation identity differs from retained plan")
    attempt = result.attempt
    if attempt:
        if json.loads(read(directory / "execution/result.json", LIMIT)) != attempt.model_dump(
            mode="json"
        ):
            raise ValueError("Embedded attempt differs from retained execution")
        if (
            attempt.source_fingerprint != selected.source_fingerprint
            or attempt.onboarding.source_fingerprint != selected.source_fingerprint
            or attempt.prepared.source_fingerprint != selected.source_fingerprint
            or attempt.prepared.plan_sha256 != attempt.plan_sha256
            or attempt.onboarding.application != attempt.prepared.application
        ):
            raise ValueError("Attempt provenance differs from selected source")
        try:
            verify_attempt(directory / "execution", attempt)
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("Malformed execution transcript") from exc
    assert entry is not None
    if decision(entry, selected.scanner_source_state, attempt) != result.decision:
        raise ValueError("Edited assessment or contradictory observations")
    return result


def write_injection_report(
    *,
    scan: Path,
    investigations: dict[str, Path],
    config: Path | None,
    plan: Path,
    validations: tuple[Path, ...],
    output: Path,
) -> None:
    raw = read(plan, LIMIT)
    selected = Plans.model_validate_json(raw)
    if selected != plan_injections(scan, investigations, config):
        raise ValueError("Edited injection plan or changed evidence")
    results = [verify_result(p, selected, raw) for p in validations]
    if len({r.finding_id for r in results}) != len(results):
        raise ValueError("Select one validation attempt per occurrence explicitly")
    if any(
        a.resolve().is_relative_to(b.resolve())
        for source in (
            scan,
            plan,
            *investigations.values(),
            *validations,
            *((config,) if config else ()),
        )
        for a, b in ((output, source), (source, output))
    ):
        raise ValueError("Output must be separate from evidence")
    paths = {
        p.path.id: p.path
        for key, directory in investigations.items()
        for r in verified_investigation(scan, directory, key)[1].results
        for p in r.paths
    }
    by_id = {r.finding_id: r for r in results}
    rows: list[dict[str, Any]] = []
    cards = []
    json_budget = html_budget = 0
    for entry in selected.entries:
        result = by_id.get(entry.finding_id)
        outcome = (
            result.decision.model_dump()
            if result
            else decision(entry, selected.scanner_source_state, None).model_dump()
            if entry.status == "blocked"
            else {"classification": "inconclusive", "reason": "not_executed"}
        )
        rows.append(
            {
                "finding": entry.model_dump(mode="json"),
                "decision": outcome,
                "validation": result.model_dump(mode="json") if result else None,
            }
        )
        body = ""
        modeled = []
        for path_id in entry.path_ids:
            path = paths[path_id]
            modeled.append(path.model_dump(mode="json"))
            body += "<h3>Modeled source-to-sink path</h3><ol>"
            for location in path.locations:
                line = (
                    read_local(scan / "snapshot", location.path, 8 * 1024 * 1024)
                    .decode("utf-8")
                    .splitlines()[location.start_line - 1]
                )
                body += (
                    "<li><code>"
                    + escape(location.path + ":" + str(location.start_line))
                    + "</code> — <code>"
                    + escape(line.strip()[:240])
                    + "</code></li>"
                )
            body += "</ol>"
        rows[-1]["modeled_paths"] = modeled
        json_budget += len(json.dumps(rows[-1]).encode())
        if json_budget > LIMIT:
            raise ValueError("Injection report JSON exceeds the size limit")
        if result and result.attempt and result.attempt.observation:
            observed = result.attempt.observation.get("validation")
            if observed:
                body += "<h3>Exact requests</h3><table><tr><th>Role</th><th>Request</th><th>Status</th><th>Response digest</th><th>Marker observed</th></tr>"
                for item in [{"role": "control", **observed["control"]}, *observed["attempts"]]:
                    body += (
                        "<tr>"
                        + "".join(
                            "<td>" + escape(str(x)) + "</td>"
                            for x in (
                                item["role"],
                                item["method"] + " " + item["target"],
                                item["status"],
                                item["body_sha256"],
                                item["marker_present"],
                            )
                        )
                        + "</tr>"
                    )
                body += "</table>"
        cards.append(
            "<article><h2>"
            + escape(entry.finding_id)
            + "</h2><p>"
            + escape(str(entry.capability or entry.rule_id))
            + " · "
            + escape(outcome["classification"])
            + " · "
            + escape(outcome["reason"])
            + "</p><p>Static result: "
            + escape(entry.result_id or "none")
            + "; paths: "
            + escape(", ".join(entry.path_ids) or "none")
            + "</p>"
            + body
            + "<details><summary>Plan, provenance and complete retained evidence</summary><pre>"
            + escape(json.dumps(rows[-1], indent=2))
            + "</pre></details></article>"
        )
        html_budget += len(cards[-1].encode())
        if html_budget > LIMIT:
            raise ValueError("Injection report HTML exceeds the size limit")
    counts = {
        "findings": len(rows),
        "supported_mappings": sum(e.capability is not None for e in selected.entries),
        "drafts_with_correlated_paths": sum(e.status == "draft" for e in selected.entries),
        "attempts": sum(r.attempt is not None for r in results),
        "completed_tests": sum(
            r.attempt is not None and r.attempt.outcome == "completed" for r in results
        ),
    }
    document = {
        "schema_version": "1.0",
        "profile": "injection-report-v1",
        "plans_sha256": digest(raw),
        "source_fingerprint": selected.source_fingerprint,
        "counts": counts,
        "findings": rows,
    }
    html = (
        """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>VulnProof injection evidence</title><style>body{font:16px system-ui;max-width:1200px;margin:2rem auto;padding:1rem;color:#182534;background:#f3f6fa}article{background:white;padding:1.5rem;margin:1rem 0;border:1px solid #cad4e2;border-radius:10px}h2,td,pre{overflow-wrap:anywhere}pre{white-space:pre-wrap;font-size:13px}table{width:100%;table-layout:fixed;border-collapse:collapse}td,th{padding:.6rem;border:1px solid #cad4e2;text-align:left;font-size:13px}.flow{display:flex;gap:.5rem;flex-wrap:wrap}.flow span{background:#dce8f8;padding:.7rem;border-radius:6px}</style><h1>Injection evidence</h1><p>Unsuccessful tests never establish safety. Each capability covers a bounded tested behavior.</p><div class="flow"><span>SARIF occurrences</span>→<span>Verified source snapshot</span>→<span>Pinned CodeQL paths</span>→<span>Discovered GET/query binding</span>→<span>Authorized fresh sandbox</span>→<span>Legitimate control</span>→<span>Independent observer probes</span>→<span>Cleanup and assessment</span></div>"""
        + "<p>"
        + escape(json.dumps(counts))
        + "</p>"
        + "".join(cards)
        + "</html>"
    )
    output.mkdir(mode=0o700)
    publish(output / "report.json", json.dumps(document, indent=2) + "\n")
    publish(output / "report.html", html)
