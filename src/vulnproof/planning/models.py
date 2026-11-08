"""Data-only draft plans. Structural validity never authorizes execution."""

from typing import Literal, Self

from pydantic import Field, model_validator

from vulnproof.correlation.models import CorrelationDocument, FindingCorrelation
from vulnproof.models import Reason
from vulnproof.models.common import Contract, Identifier, Sha256


class FixtureBinding(Contract):
    fixture_id: Identifier
    method: Literal["GET"]
    route: Literal["/download"]
    input_location: Literal["query"]
    input_name: Literal["name"]
    download_root: Literal["/fixture/downloads"]
    legitimate_document: Literal["example.txt"]
    legitimate_document_sha256: Sha256
    template_id: Literal["cwe22-file-read-v1"]


class RequestCheck(Contract):
    kind: Literal["legitimate_request", "parent_traversal", "absolute_path"]
    role: Literal["control", "probe"]
    input_value: Literal[
        "legitimate_document", "runtime_parent_canary_path", "runtime_absolute_canary_path"
    ]
    positive_status: Literal[200]
    exact_body: Literal["legitimate_document", "fresh_canary"]


class CanaryRequirements(Contract):
    kind: Literal["prepare_canary"]
    directory: Literal["/tmp/vulnproof"]
    fresh_nonce_bytes: Literal[32]
    require_initial_absence: Literal[True]
    outside_download_root: Literal[True]


class ValidationTemplate(Contract):
    id: Literal["cwe22-file-read-v1"]
    cwe: Literal["CWE-22"]
    steps: tuple[RequestCheck, CanaryRequirements, RequestCheck, RequestCheck]
    control_failure: Literal["stop_probes_no_conclusion"]
    unsuccessful_probe: Literal["no_safety_conclusion"]
    response_limit_bytes: Literal[65536]
    request_timeout_seconds: Literal[3]

    @model_validator(mode="after")
    def ordered_checks(self) -> Self:
        control, _, parent, absolute = self.steps
        if (
            (control.kind, control.role, control.input_value, control.exact_body)
            != ("legitimate_request", "control", "legitimate_document", "legitimate_document")
            or (parent.kind, parent.role, parent.input_value, parent.exact_body)
            != ("parent_traversal", "probe", "runtime_parent_canary_path", "fresh_canary")
            or (absolute.kind, absolute.role, absolute.input_value, absolute.exact_body)
            != ("absolute_path", "probe", "runtime_absolute_canary_path", "fresh_canary")
        ):
            raise ValueError("template must retain the reviewed control/canary/probe sequence")
        return self


class ExecutionRequirements(Contract):
    id: Literal["fixture-isolation-v1"]
    non_root: Literal[True]
    read_only_root: Literal[True]
    network: Literal["none"]
    published_ports: Literal[False]
    host_mounts: Literal[False]
    drop_capabilities: Literal["ALL"]
    no_new_privileges: Literal[True]
    cpus: Literal[1]
    memory_bytes: Literal[268435456]
    pids: Literal[64]
    temporary_bytes: Literal[16777216]
    temporary_noexec_nosuid_nodev: Literal[True]
    deadline_seconds: Literal[60]
    output_limit_bytes: Literal[1048576]
    transport: Literal["container_loopback"]
    fresh_container: Literal[True]
    cleanup_all_outcomes: Literal[True]
    dependency_installation: Literal[False]
    repository_builds: Literal[False]


class PlanningCatalog(Contract):
    schema_version: Literal["1.0"]
    id: Literal["fixture-planning-v1"]
    bindings: tuple[FixtureBinding, ...] = Field(min_length=1)
    template: ValidationTemplate
    execution: ExecutionRequirements

    @model_validator(mode="after")
    def unique_bindings(self) -> Self:
        ids = [b.fixture_id for b in self.bindings]
        if len(ids) != len(set(ids)):
            raise ValueError("fixture bindings must be unique")
        return self


class DraftPlan(Contract):
    fixture_id: Identifier
    template_id: Literal["cwe22-file-read-v1"]
    execution_policy_id: Literal["fixture-isolation-v1"]
    candidate_result_id: Identifier
    path_ids: tuple[Identifier, ...] = Field(min_length=1)
    execution_authorized: Literal[False] = False
    scanner_source_state: Literal["unverified"] = "unverified"
    unmet_prerequisites: tuple[Reason, ...] = Field(min_length=1)


class FindingPlan(Contract):
    finding_id: Identifier
    disposition: Literal["draft", "blocked"]
    plan: DraftPlan | None = None
    reasons: tuple[Reason, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def draft_present(self) -> Self:
        if (self.disposition == "draft") != (self.plan is not None):
            raise ValueError("only draft dispositions may carry a plan")
        return self


def block_reason(correlation: CorrelationDocument, item: FindingCorrelation) -> str | None:
    """One shared eligibility rule for producers and structural validation."""
    if correlation.analysis_normalization == "partial":
        return "analysis_partial"
    if item.status != "single_candidate":
        return item.status
    return None


class PlanningDocument(Contract):
    schema_version: Literal["1.0"]
    catalog_id: Literal["fixture-planning-v1"]
    catalog_sha256: Sha256
    correlation_sha256: Sha256
    correlation: CorrelationDocument
    fixture: FixtureBinding
    template: ValidationTemplate
    execution_requirements: ExecutionRequirements
    findings: tuple[FindingPlan, ...]

    @model_validator(mode="after")
    def reference_graph(self) -> Self:
        if tuple(f.finding_id for f in self.findings) != tuple(
            f.imported.finding.id for f in self.correlation.findings
        ):
            raise ValueError("planning must retain each correlation occurrence in order")
        for entry, original in zip(self.findings, self.correlation.findings, strict=True):
            if (entry.disposition == "blocked") != (
                block_reason(self.correlation, original) is not None
            ):
                raise ValueError("disposition disagrees with correlation eligibility")
            plan = entry.plan
            if plan is None:
                continue
            candidate = original.candidates[0]
            if (
                plan.fixture_id != self.fixture.fixture_id
                or plan.template_id != self.template.id
                or plan.execution_policy_id != self.execution_requirements.id
                or plan.candidate_result_id != candidate.id
                or plan.path_ids != tuple(p.path.id for p in candidate.paths)
            ):
                raise ValueError("draft references must retain the selected group and all paths")
            required = {
                "scanner_source_unverified",
                "execution_authorization_required",
                "approved_image_required",
                "runtime_oracle_required",
            }
            if not required.issubset({r.code for r in plan.unmet_prerequisites}):
                raise ValueError("draft must retain unmet provenance and execution prerequisites")
        return self
