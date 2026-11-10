"""Show the retained scanner-to-container chain without inventing stage completion."""

from vulnproof.models import ExecutionEvidence, StaticEvidence
from vulnproof.validation.models import Attempt

from .markup import text
from .models import ReportDocument


def artifact_status(report: ReportDocument, identity: str) -> str:
    check = next((c for c in report.artifacts if c.artifact.id == identity), None)
    return check.status if check else "not supplied"


def step(number: int, title: str, facts: tuple[str, ...], *, attention: bool = False) -> str:
    return (
        '<li><div class="pipeline-step'
        + (" needs-attention" if attention else "")
        + '"><strong><span class="step-number">'
        + str(number)
        + "</span> "
        + text(title)
        + "</strong><ul>"
        + "".join("<li>" + text(fact) + "</li>" for fact in facts)
        + "</ul></div></li>"
    )


def selected(
    report: ReportDocument,
) -> tuple[StaticEvidence | None, ExecutionEvidence | None, Attempt | None]:
    assessment = report.evidence.assessment
    static = next(
        (
            s
            for s in report.evidence.static_evidence
            if assessment and s.id == assessment.static_evidence_id
        ),
        None,
    )
    execution = next(
        (
            e
            for e in report.evidence.execution_evidence
            if assessment and e.id == assessment.execution_evidence_id
        ),
        None,
    )
    detail = next((d for d in report.runtime if execution and d.execution_id == execution.id), None)
    return static, execution, detail.attempt if detail and detail.status == "available" else None


def render_pipeline(report: ReportDocument) -> str:
    bundle = report.evidence
    finding = bundle.finding
    assessment = bundle.assessment
    static, execution, attempt = selected(report)
    snapshot = next(
        (s for s in bundle.snapshots if s.id == finding.source.observed_snapshot_id), None
    )
    source_state = {
        "matched": "Matched: finding and captured source are linked",
        "unverified": "Unverified: scanner-to-source relationship is not established",
        "mismatched": "Mismatched: source identities disagree",
    }[finding.source.state]
    source_facts = [source_state]
    if snapshot:
        source_facts.append(f"{len(snapshot.files)} captured source file(s)")
        source_facts.append(
            "Revision: " + (snapshot.commit_id[:12] if snapshot.commit_id else "unknown")
        )
        source_facts.append(
            "Captured scope: "
            + (
                "unknown working-tree state"
                if snapshot.dirty is None
                else "dirty"
                if snapshot.dirty
                else "clean"
            )
        )
    else:
        source_facts.append("No observed source identity linked to this finding")
    source_facts.append(
        "Controlled-scan receipt: " + artifact_status(report, "scan-proof:scan:receipt")
    )
    scanner_facts = (
        f"Scanner: {finding.scanner.name} {finding.scanner.version or '(version unknown)'}",
        "Rule: " + finding.rule_id,
        f"Finding: {finding.location.path}:{finding.location.start_line}",
        "Normalized ingestion artifact: " + artifact_status(report, "validation:ingestion"),
    )
    static_facts: tuple[str, ...]
    authorization: tuple[str, ...]
    sandbox: tuple[str, ...]
    if static:
        static_facts = (
            f"Tool: {static.tool.name} {static.tool.version or '(version unknown)'}",
            "Query: " + (static.rule_id or "not recorded"),
            "Modeled outcome: " + static.outcome,
            f"{len(static.paths)} retained path(s); static analysis does not prove runtime exploitability",
        )
    else:
        static_facts = (
            "No static evidence selected by this assessment",
            f"{len(bundle.static_evidence)} static record(s) retained in technical evidence",
        )
    path_selected = (
        static is not None and assessment is not None and assessment.static_path_id is not None
    )
    linked = (
        execution is not None
        and assessment is not None
        and execution.static_evidence_id == assessment.static_evidence_id
        and execution.static_path_id == assessment.static_path_id
        and path_selected
    )
    plan_facts = (
        "Selected path: "
        + (
            "explicit reference retained"
            if path_selected
            else "none; no path chosen by this report"
        ),
        "Execution-to-path link: " + ("recorded" if linked else "not established"),
        "Retained plan artifact: " + artifact_status(report, "validation:plan"),
        "A plan describes the test; it does not authorize execution",
    )
    if attempt:
        authorization = (
            "Explicit validation authorization is recorded",
            "Scope: " + attempt.authorization_scope,
            "Prepared-image receipt: " + artifact_status(report, "validation:preparation"),
            "Immutable image ID recorded; full identity in technical evidence",
        )
        sandbox = (
            "Container execution: " + attempt.execution,
            "Runner policy check: "
            + ("recorded as passed" if attempt.policy_verified else "not verified"),
            "Fixed profile requires: non-root, read-only root, dropped capabilities, no external network",
            "Profile limits: 1 CPU, 256 MiB memory, 64 processes, 16 MiB temporary storage; 60-second attached execution deadline",
        )
        driver = attempt.driver
        observations = ["Driver: " + (driver.outcome if driver else "no supported driver record")]
        if driver:
            observations.append(
                "Legitimate-request control: "
                + ("passed" if driver.control_valid else "not passed / unavailable")
            )
            observations.append(f"{len(driver.probes)} probe response(s) recorded")
            observations.append(
                "Exact fresh-canary disclosure: "
                + ("observed" if driver.observed else "not observed")
            )
        observations.append(
            "Cleanup: "
            + (
                "container absence verified"
                if attempt.cleanup == "verified_absent"
                else "container absence NOT verified"
                if attempt.cleanup == "unverified"
                else "no removal needed"
            )
        )
        runtime_attention = attempt.execution != "completed" or not attempt.policy_verified
        observation_attention = (
            attempt.cleanup == "unverified" or driver is None or driver.outcome != "completed"
        )
    else:
        authorization = (
            "Supported authorization and prepared-image details unavailable",
            "Missing records do not imply authorization",
        )
        sandbox = (
            "No supported container attempt can be displayed",
            "This report does not assume a container ran",
        )
        observations = [
            "Bundle execution: " + (execution.outcome if execution else "none selected"),
            "Bundle oracle: " + (execution.oracle if execution else "none selected"),
            "Driver and cleanup details unavailable",
        ]
        runtime_attention = observation_attention = True
    result_facts = (
        "Recorded assessment: " + (assessment.classification if assessment else "unassessed"),
        "Retained artifact integrity: " + report.integrity,
        "Positive disclosure can remain recorded when later failure prevents confirmation",
        "No disclosure, missing paths, or unsuccessful tests never establish safety",
    )
    return (
        '<section class="pipeline-overview"><h3>Investigation end to end</h3>'
        "<p>Follow the finding from scanner output to the recorded decision. Each card summarizes retained records; unavailable stages are labeled, not assumed successful.</p>"
        '<div class="pipeline-phases"><section class="pipeline-phase"><h4>Semgrep / SARIF → source</h4><ol class="pipeline-steps">'
        + step(1, "Scanner finding & normalization", scanner_facts)
        + step(
            2,
            "Bind exact source and revision",
            tuple(source_facts),
            attention=finding.source.state != "matched",
        )
        + '</ol></section><section class="pipeline-phase"><h4>CodeQL → validation plan</h4><ol class="pipeline-steps">'
        + step(
            3,
            "Analyze modeled reachability",
            static_facts,
            attention=static is None or static.outcome != "path_found",
        )
        + step(
            4,
            "Correlate finding, path, and plan",
            plan_facts,
            attention=not linked or artifact_status(report, "validation:plan") != "verified",
        )
        + '</ol></section><section class="pipeline-phase"><h4>Container → observations → result</h4><ol class="pipeline-steps">'
        + step(5, "Authorize the approved fixture", authorization, attention=attempt is None)
        + step(6, "Run the restricted Docker test", sandbox, attention=runtime_attention)
        + step(
            7,
            "Observe controls, probes, cleanup",
            tuple(observations),
            attention=observation_attention,
        )
        + step(
            8,
            "Correlate evidence and classify",
            result_facts,
            attention=report.integrity != "verified"
            or assessment is None
            or assessment.classification != "confirmed",
        )
        + '</ol></section></div><p class="muted">Static analysis and scanner processing are separate from container execution. The Docker boundary applies to fixture execution; this diagram does not imply native analysis tools ran inside Docker. Artifact status means local byte checks, not a rerun or producer authentication.</p>'
        "</section>"
    )
