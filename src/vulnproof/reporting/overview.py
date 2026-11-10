"""A readable evidence story; modeled flow stays distinct from runtime observations."""

import posixpath
from itertools import groupby

from vulnproof.models import SourceLocation, StaticPath

from .markup import text
from .models import ReportDocument
from .pipeline import render_pipeline

MAX_EXCERPT_CHARS = 240


def source_line(report: ReportDocument, snapshot_id: str | None, loc: SourceLocation) -> str | None:
    snapshot = next((s for s in report.evidence.snapshots if s.id == snapshot_id), None)
    if snapshot is None:
        return None
    source = next((f for f in snapshot.files if f.path == loc.path), None)
    if source is None:
        return None
    check = next(
        (
            c
            for c in report.artifacts
            if c.status == "verified"
            and c.artifact.path == "evidence/source/" + loc.path
            and c.observed_sha256 == source.sha256
            and c.preview_encoding == "utf-8"
            and not c.preview_truncated
        ),
        None,
    )
    if check is None:
        return None
    lines = check.preview.splitlines()
    if loc.start_line > len(lines):
        return None
    line = lines[loc.start_line - 1].strip()
    return line[:MAX_EXCERPT_CHARS] + (
        " … [excerpt shortened]" if len(line) > MAX_EXCERPT_CHARS else ""
    )


def node(title: str, description: str, code: str | None = None) -> str:
    return (
        '<li><div class="flow-node"><strong>'
        + text(title)
        + "</strong><p>"
        + text(description)
        + "</p>"
        + ("<pre>" + text(code) + "</pre>" if code is not None else "")
        + "</div></li>"
    )


def modeled_flow(report: ReportDocument, path: StaticPath, snapshot_id: str | None) -> str:
    groups = [
        (key, tuple(locations))
        for key, locations in groupby(
            path.locations, lambda loc: (loc.path, loc.start_line, loc.end_line)
        )
    ]
    visible = (
        list(range(len(groups)))
        if len(groups) <= 8
        else [0, 1, 2, -1, len(groups) - 3, len(groups) - 2, len(groups) - 1]
    )
    nodes = []
    for index in visible:
        if index == -1:
            nodes.append(
                node(
                    "Intermediate steps",
                    f"{len(groups) - 6} grouped steps omitted from this overview; the full path is preserved below.",
                )
            )
            continue
        _, locations = groups[index]
        loc = locations[0]
        line = source_line(report, snapshot_id, loc)
        label = (
            "Modeled source"
            if index == 0
            else "Modeled sink"
            if index == len(groups) - 1
            else "Propagation step"
        )
        # Labels describe visible source syntax; they do not infer an execution trace.
        if line and "from flask import" in line:
            label = "Flask request model"
        elif line and "request.args.get(" in line:
            label = "Read the request parameter"
        elif line and "os.path.join(" in line:
            label = "Build the file path"
        elif line and "open(" in line and index == len(groups) - 1:
            label = "Read the file"
        description = f"{loc.path}, line {loc.start_line}"
        if len(locations) > 1:
            description += f" · {len(locations)} modeled locations grouped"
        nodes.append(
            node(
                label,
                description,
                line
                if line
                else "Source excerpt unavailable; location is retained from static analysis.",
            )
        )
    return '<ol class="flow">' + "".join(nodes) + "</ol>"


def render_overview(report: ReportDocument) -> str:
    bundle = report.evidence
    assessment = bundle.assessment
    static = next(
        (s for s in bundle.static_evidence if assessment and s.id == assessment.static_evidence_id),
        None,
    )
    path = (
        next((p for p in static.paths if assessment and p.id == assessment.static_path_id), None)
        if static
        else None
    )
    execution = next(
        (
            e
            for e in bundle.execution_evidence
            if assessment and e.id == assessment.execution_evidence_id
        ),
        None,
    )
    detail = next((d for d in report.runtime if execution and d.execution_id == execution.id), None)
    attempt = detail.attempt if detail and detail.status == "available" else None
    driver = attempt.driver if attempt else None
    heading = "Path traversal" if "CWE-22" in bundle.finding.cwes else "Finding overview"
    parts = [
        '<section class="overview"><h2>'
        + text(heading)
        + " at "
        + text(f"{bundle.finding.location.path}:{bundle.finding.location.start_line}")
        + "</h2>"
    ]
    if driver and driver.observed:
        parts.append(
            '<p class="story">The application returned the exact contents of a fresh test file outside its download directory. This demonstrates file access beyond the intended download folder in this recorded fixture test.</p>'
        )
        if assessment and assessment.classification != "confirmed":
            parts.append(
                '<div class="notice"><strong>Disclosure was observed, but this finding is not confirmed.</strong> Read the recorded decision and its reasons below; provenance or operational requirements may still be unmet.</div>'
            )
    elif driver and driver.outcome == "completed":
        parts.append(
            '<p class="story">The recorded probes did not disclose the fresh test file. These bounded attempts do not establish that the application is safe.</p>'
        )
    else:
        parts.append(
            '<p class="story">The record does not provide complete supported runtime observations for this overview. Modeled reachability and a stored assessment alone are not an observed exploit trace.</p>'
        )
    parts.append(render_pipeline(report))
    parts.append(
        '<div class="flow-grid"><section><h3>1. Modeled data flow</h3><p>CodeQL’s selected path. Arrows show modeled propagation, not a runtime trace.</p>'
    )
    if path and static:
        parts.append(modeled_flow(report, path, static.source.observed_snapshot_id))
    else:
        parts.append(
            '<div class="notice">No static path is selected for this assessment. Available paths remain in the technical details; this overview does not choose one.</div>'
        )
    parts.append(
        "</section><section><h3>2. Recorded runtime checks</h3><p>Observations from the fixture driver, correlated with the selected path. Requests are not rerun when reporting.</p>"
    )
    if attempt and driver:
        runtime = []
        runtime.append(
            node(
                "Control: legitimate download",
                "HTTP 200 · expected document returned"
                if driver.control_valid
                else "No control response was recorded"
                if driver.control is None
                else "Control did not pass; probes cannot establish confirmation.",
            )
        )
        if driver.canary:
            runtime.append(
                node(
                    "Fresh canary outside the download folder",
                    "A synthetic file was created under /tmp/vulnproof, outside /fixture/downloads.",
                )
            )
        for probe in driver.probes:
            matched = (
                driver.canary is not None
                and probe.status == 200
                and probe.body == driver.canary.body
            )
            runtime.append(
                node(
                    "Parent-directory traversal"
                    if probe.kind == "parent_traversal"
                    else "Absolute-path probe",
                    f"HTTP {probe.status} · "
                    + (
                        "exact canary contents returned"
                        if matched
                        else "no exact canary disclosure"
                    )
                    + " · input pattern below has an abbreviated filename",
                    "name=../../tmp/vulnproof/[fresh-file].txt"
                    if probe.kind == "parent_traversal"
                    else "name=/tmp/vulnproof/[fresh-file].txt",
                )
            )
        runtime.append(
            node(
                "Container cleanup",
                "Container absence verified"
                if attempt.cleanup == "verified_absent"
                else "Container absence not verified"
                if attempt.cleanup == "unverified"
                else "No container needed removal",
            )
        )
        parts.append('<ol class="flow runtime-flow">' + "".join(runtime) + "</ol>")
        if driver.canary and driver.probes:
            parts.append(
                "<details><summary>Show reconstructed probe inputs</summary><p>Derived from recorded probe kinds, the retained canary path, and the fixed fixture driver. The random filename is test data.</p>"
            )
            for probe in driver.probes:
                value = (
                    posixpath.relpath(driver.canary.path, "/fixture/downloads")
                    if probe.kind == "parent_traversal"
                    else driver.canary.path
                )
                label = (
                    "Parent-directory input"
                    if probe.kind == "parent_traversal"
                    else "Absolute-path input"
                )
                parts.append("<p>" + text(label) + ":</p><pre>name=" + text(value) + "</pre>")
            parts.append("</details>")

    else:
        parts.append(
            '<div class="notice">Runtime details are unavailable or failed consistency checks. This report cannot reconstruct the test sequence from verified supporting records.</div>'
        )
    parts.append(
        '</section></div><p class="muted">These two views represent different evidence: modeled reachability on the left, retained runtime observations on the right. Grouped locations and shortened excerpts do not replace the full evidence records.</p></section>'
    )
    return "".join(parts)
