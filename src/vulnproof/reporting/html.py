"""Passive HTML: only fixed markup and CSS; all evidence values are escaped text."""

import base64
import hashlib
from collections.abc import Iterable
from html import escape

from vulnproof.models import Reason, SourceBinding, SourceLocation
from vulnproof.validation.models import Response

from .markup import text
from .models import ReportDocument
from .overview import render_overview
from .prepare import MAX_PREVIEW_BYTES, preview

CSS = """
:root { color-scheme: light; font-family: system-ui, sans-serif; color: #192b3d; background: #f3f5f7; }
body { margin: 0; } main { max-width: 1120px; margin: auto; padding: 32px 20px 64px; }
header { border-top: 5px solid #285a80; padding: 24px; background: white; }
h1 { font-size: 28px; margin: 0 0 8px; } h2 { margin-top: 32px; font-size: 21px; }
h3 { font-size: 17px; } p { line-height: 1.6; } .muted { color: #526477; }
.notice { border-left: 5px solid #9c5700; background: #fff3dd; padding: 12px 16px; margin: 16px 0; }
.integrity { font-weight: 700; } .verified { border-color: #21634d; background: #eaf5ef; }
.table { overflow-x: auto; background: white; border: 1px solid #d2dae2; margin: 12px 0; }
table { border-collapse: collapse; width: 100%; text-align: left; }
th, td { padding: 10px 12px; vertical-align: top; border-bottom: 1px solid #e1e6eb; overflow-wrap: anywhere; }
th { background: #eaf0f5; } td:first-child { min-width: 130px; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; padding: 14px; background: #eef1f5; font-size: 13px; }
code, pre { font-family: ui-monospace, monospace; } details { margin: 12px 0; }
summary { cursor: pointer; font-weight: 600; } li { margin: 7px 0; line-height: 1.5; }
.overview { background: white; padding: 4px 24px 24px; border: 1px solid #d2dae2; }
.story { font-size: 19px; max-width: 880px; }
.pipeline-phases { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 24px; }
.pipeline-phase { min-width: 0; position: relative; }
.pipeline-phase h4 { padding: 12px; border-bottom: 3px solid #285a80; background: #eaf0f5; margin: 0 0 16px; }
.pipeline-phase:not(:last-child)::after { content: "→"; position: absolute; right: -22px; top: 10px; color: #526477; font-size: 23px; }
.pipeline-steps { padding: 0; margin: 0; list-style: none; }
.pipeline-steps > li { margin: 0; }
.pipeline-steps > li:not(:last-child)::after { content: "↓"; display: block; text-align: center; color: #526477; font-size: 22px; }
.pipeline-step { border: 1px solid #b7cbdc; background: #f2f7fb; border-radius: 6px; padding: 12px; overflow-wrap: anywhere; }
.pipeline-step ul { padding-left: 18px; font-size: 13px; }
.pipeline-step.needs-attention { background: #fff6e6; border-color: #ba8c3d; }
.step-number { color: #285a80; font-size: 19px; }
@media (max-width: 900px) { .pipeline-phases { grid-template-columns: minmax(0,1fr); } .pipeline-phase:not(:last-child)::after { display: none; } }
.flow-grid { display: grid; grid-template-columns: minmax(0,1fr) minmax(0,1fr); gap: 28px; }
.flow { list-style: none; padding: 0; margin: 20px 0; }
.flow li { margin: 0; }
.flow li:not(:last-child)::after { content: "↓"; display: block; text-align: center; font-size: 24px; color: #526477; }
.flow-node { border: 1px solid #b7cbdc; border-left: 4px solid #285a80; border-radius: 6px; background: #f2f7fb; padding: 14px; overflow-wrap: anywhere; }
.flow-node p { margin: 5px 0 0; font-size: 14px; }
.flow-node pre { margin: 10px 0 0; background: white; }
.runtime-flow .flow-node { border-left-color: #81622e; background: #faf7ef; }
.technical > summary { padding: 18px; border: 1px solid #d2dae2; background: white; font-size: 19px; }
@media (max-width: 760px) { .flow-grid { grid-template-columns: minmax(0,1fr); } .overview { padding: 4px 14px 18px; } }
section { margin: 20px 0; } .record { padding: 4px 20px 16px; border: 1px solid #d2dae2; background: white; }
@media (max-width: 600px) { main { padding: 16px 10px; } header { padding: 16px; } th,td { padding: 8px; } }
""".strip()


def table(headings: tuple[str, ...], rows: Iterable[tuple[object, ...]]) -> str:
    head = "".join('<th scope="col">' + text(h) + "</th>" for h in headings)
    body = "".join(
        "<tr>" + "".join("<td>" + text(v) + "</td>" for v in row) + "</tr>" for row in rows
    )
    return (
        '<div class="table"><table><thead><tr>'
        + head
        + "</tr></thead><tbody>"
        + body
        + "</tbody></table></div>"
    )


def reasons(items: tuple[Reason, ...]) -> str:
    return (
        "<ul>"
        + "".join(
            "<li><code>" + text(r.code) + "</code>: " + text(r.message) + "</li>" for r in items
        )
        + "</ul>"
        if items
        else "<p>No reasons recorded.</p>"
    )


def binding(value: SourceBinding) -> str:
    return table(
        ("Source relationship", "Recorded value"),
        (
            ("State", value.state),
            ("Expected snapshot", value.expected_snapshot_id),
            ("Observed snapshot", value.observed_snapshot_id),
            ("Reason", value.reason.message),
        ),
    )


def location(value: SourceLocation) -> str:
    return f"{value.path}:{value.start_line}" + (
        f":{value.start_column}" if value.start_column else ""
    )


def response(value: Response) -> str:
    encoding, sample, truncated = preview(value.body, MAX_PREVIEW_BYTES)
    return (
        table(
            ("Response observation", "Value"),
            (
                ("HTTP status", value.status),
                ("Body bytes", len(value.body)),
                ("Body SHA-256", hashlib.sha256(value.body).hexdigest()),
                ("Preview encoding", encoding),
                ("Preview omitted bytes", truncated),
            ),
        )
        + "<pre>"
        + text(sample)
        + "</pre>"
    )


def render_html(report: ReportDocument) -> str:
    bundle = report.evidence
    assessment = bundle.assessment
    recorded = assessment.classification if assessment else "unassessed"
    style_hash = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode("ascii")
    policy = (
        "default-src 'none'; style-src 'sha256-"
        + style_hash
        + "'; base-uri 'none'; form-action 'none'"
    )
    sections = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="' + escape(policy, quote=True) + '">',
        "<title>VulnProof evidence report</title><style>" + CSS + "</style></head><body><main>",
        '<header><h1>VulnProof evidence report</h1><p class="muted">One finding · retained evidence · offline report</p>',
        "<p><strong>Recorded assessment: " + text(recorded) + "</strong></p>",
        '<div class="notice integrity'
        + (" verified" if report.integrity == "verified" else "")
        + '">Retained artifact integrity: '
        + text(report.integrity)
        + "</div>",
        "<p>Artifact integrity describes local bytes and metadata. It does not authenticate the producer or repeat validation.</p></header>",
        render_overview(report),
        "<h2>Recorded decision and evidence limitations</h2>",
        "<ul>" + "".join("<li>" + text(r.message) + "</li>" for r in assessment.reasons) + "</ul>"
        if assessment
        else "<p>No assessment has been recorded.</p>",
        "<p>"
        + text(
            {
                "matched": "The scanner finding and source are linked to the same captured bytes.",
                "unverified": "The scanner finding has not been tied to the captured source bytes.",
                "mismatched": "The finding and source identities do not match.",
            }[bundle.finding.source.state]
        )
        + "</p>",
        "<ul>"
        + "".join(
            "<li>" + text(r.message) + "</li>"
            for r in report.warnings
            if r.code != "recorded_assessment_only"
        )
        + "</ul>",
        '<details class="technical"><summary>Inspect technical evidence: paths, provenance, hashes, and raw observations</summary>',
        "<h2>Limitations and integrity warnings</h2>",
        reasons(report.warnings),
        "<p>An unsuccessful probe never establishes safety. Missing paths, errors, and timeouts do not prove a finding safe.</p>",
        "<h2>Finding and recorded decision</h2>",
        table(
            ("Field", "Recorded value"),
            (
                ("Finding ID", bundle.finding.id),
                ("Rule", bundle.finding.rule_id),
                ("CWE", ", ".join(bundle.finding.cwes) or "not recorded"),
                ("Location", location(bundle.finding.location)),
                ("Original reference", bundle.finding.original_ref),
                ("Scanner", bundle.finding.scanner.name),
                ("Scanner version", bundle.finding.scanner.version),
                ("Selected static evidence", assessment.static_evidence_id if assessment else None),
                ("Selected path", assessment.static_path_id if assessment else None),
                ("Selected execution", assessment.execution_evidence_id if assessment else None),
            ),
        ),
        reasons(assessment.reasons) if assessment else "<p>No assessment has been recorded.</p>",
        "<h3>Finding source association</h3>",
        binding(bundle.finding.source),
        "<h2>Source snapshots and revision</h2>",
    ]
    for snapshot in bundle.snapshots:
        dirty = (
            "unknown"
            if snapshot.dirty is None
            else "dirty within captured scope"
            if snapshot.dirty
            else "clean within captured scope"
        )
        sections.extend(
            (
                '<section class="record"><h3>' + text(snapshot.id) + "</h3>",
                table(
                    ("Identity", "Recorded value"),
                    (
                        ("Fingerprint", snapshot.fingerprint),
                        ("Commit", snapshot.commit_id),
                        ("Working tree", dirty),
                    ),
                ),
                table(("Source path", "SHA-256"), ((f.path, f.sha256) for f in snapshot.files)),
                "</section>",
            )
        )
    sections.append("<h2>Modeled static reachability</h2>")
    if not bundle.static_evidence:
        sections.append("<p>No static observations recorded.</p>")
    for static in bundle.static_evidence:
        sections.extend(
            (
                '<section class="record"><h3>' + text(static.id) + "</h3>",
                table(
                    ("Field", "Recorded value"),
                    (
                        ("Outcome", static.outcome),
                        ("Tool", static.tool.name),
                        ("Tool version", static.tool.version),
                        ("Query pack", static.tool.rule_pack),
                        ("Query", static.rule_id),
                        ("CWE", static.cwe),
                    ),
                ),
                binding(static.source),
                reasons(static.reasons),
            )
        )
        for path in static.paths:
            selected = (
                assessment is not None
                and assessment.static_evidence_id == static.id
                and assessment.static_path_id == path.id
            )
            sections.append(
                "<h3>Path "
                + text(path.id)
                + (" · selected" if selected else " · alternative / unselected")
                + "</h3>"
            )
            sections.append(
                table(
                    ("Step", "Path", "Start line", "Start column", "End line", "End column"),
                    (
                        (
                            i,
                            loc.path,
                            loc.start_line,
                            loc.start_column,
                            loc.end_line,
                            loc.end_column,
                        )
                        for i, loc in enumerate(path.locations, 1)
                    ),
                )
            )
        sections.append("</section>")
    sections.append("<h2>Dynamic execution and oracle</h2>")
    if not bundle.execution_evidence:
        sections.append("<p>No execution observations recorded.</p>")
    for execution, detail in zip(bundle.execution_evidence, report.runtime, strict=True):
        sections.extend(
            (
                '<section class="record"><h3>' + text(execution.id) + "</h3>",
                table(
                    ("Field", "Recorded value"),
                    (
                        ("Outcome", execution.outcome),
                        ("Oracle", execution.oracle),
                        ("Oracle ID", execution.oracle_id),
                        ("Image ID", execution.image_id),
                        ("Target static evidence", execution.static_evidence_id),
                        ("Target path", execution.static_path_id),
                    ),
                ),
                binding(execution.source),
                reasons(execution.reasons),
            )
        )
        attempt = detail.attempt
        if attempt is None:
            sections.append(
                "<p>Structured attempt detail: "
                + text(detail.status)
                + ". "
                + text(detail.reason.message)
                + "</p>"
            )
        else:
            sections.append(
                table(
                    ("Attempt", "Recorded value"),
                    (
                        ("Container / attempt ID", attempt.attempt_id),
                        ("Fixture", attempt.fixture_id),
                        ("Authorization scope", attempt.authorization_scope),
                        ("Policy verified", attempt.policy_verified),
                        ("Cleanup", attempt.cleanup),
                        ("Container exit code", attempt.exit_code),
                        ("OOM killed", attempt.oom_killed),
                    ),
                )
            )
            sections.append(reasons(attempt.reasons))
            driver = attempt.driver
            if driver is None:
                sections.append("<p>No parsed driver observations.</p>")
            else:
                sections.append(
                    table(
                        ("Driver", "Recorded value"),
                        (
                            ("Outcome", driver.outcome),
                            ("Diagnostics passed", driver.diagnostics_passed),
                            ("Control valid", driver.control_valid),
                            ("Exact canary disclosure observed", driver.observed),
                            ("Errors", ", ".join(driver.errors) or "none"),
                        ),
                    )
                )
                if driver.control is not None:
                    sections.extend(
                        ("<h3>Legitimate request control</h3>", response(driver.control))
                    )
                if driver.canary is not None:
                    sections.append(
                        table(
                            ("Canary", "Recorded value"),
                            (
                                ("Path", driver.canary.path),
                                ("Initially absent", driver.canary.initially_absent),
                                (
                                    "Expected bytes SHA-256",
                                    hashlib.sha256(driver.canary.body).hexdigest(),
                                ),
                            ),
                        )
                    )
                for probe in driver.probes:
                    sections.extend(("<h3>Probe: " + text(probe.kind) + "</h3>", response(probe)))
            sections.append(
                table(
                    ("Command stage", "Outcome", "Exit code", "Seconds", "Log artifact"),
                    (
                        (c.stage, c.outcome, c.return_code, c.duration_seconds, c.log.id)
                        for c in attempt.commands
                    ),
                )
            )
        sections.append("</section>")
    sections.append(
        "<h2>Artifact inventory and bounded previews</h2><p>Paths are retained text, not links. Previews may omit bytes independently of artifact completeness.</p>"
    )
    if not report.artifacts:
        sections.append("<p>No artifact descriptors supplied; integrity cannot be established.</p>")
    for check in report.artifacts:
        ref = check.artifact
        sections.extend(
            (
                '<details class="record"><summary>'
                + text(ref.id)
                + " · "
                + text(check.status)
                + " · "
                + text(ref.path)
                + "</summary>",
                table(
                    ("Artifact", "Observation"),
                    (
                        ("Path", ref.path),
                        ("Declared media type", ref.media_type),
                        ("Integrity status", check.status),
                        ("Retained SHA-256", ref.sha256),
                        ("Observed SHA-256", check.observed_sha256),
                        ("Retained bytes", ref.size_bytes),
                        ("Observed bytes", check.observed_size_bytes),
                        ("Retained truncation", ref.truncated),
                        ("Preview encoding", check.preview_encoding),
                        ("Preview omitted bytes", check.preview_truncated),
                    ),
                ),
                reasons(check.reasons),
            )
        )
        if check.preview_encoding != "none":
            sections.append(
                "<details><summary>Bounded artifact preview</summary><pre>"
                + text(check.preview)
                + "</pre></details>"
            )
        sections.append("</details>")
    sections.extend(
        (
            "<h2>Report identity</h2>",
            table(
                ("Field", "Value"),
                (
                    ("Report schema", report.schema_version),
                    ("Report profile", report.profile),
                    ("Input result SHA-256", report.result_sha256),
                    ("Evidence schema", bundle.schema_version),
                ),
            ),
            '<p class="muted">The accompanying report.json preserves the full evidence contract and these report observations. Local checks are observations at report preparation time.</p>',
            "</details></main></body></html>",
        )
    )
    return "".join(sections)
