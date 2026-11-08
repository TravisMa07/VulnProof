"""Reconstruct evidence and describe a fixed investigation, without execution."""

import hashlib
from importlib.resources import files
from pathlib import Path

from vulnproof.artifacts import read_local
from vulnproof.correlation import CorrelationDocument, CorrelationFailure, correlate
from vulnproof.correlation.engine import MAX_DOCUMENT_BYTES
from vulnproof.models import Reason
from vulnproof.static.analysis import admit_fixture, fixture_manifest

from .models import DraftPlan, FindingPlan, PlanningCatalog, PlanningDocument, block_reason


class PlanningFailure(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _catalog_bytes() -> bytes:
    return files("vulnproof.planning").joinpath("catalog.json").read_bytes()


def planning_catalog() -> PlanningCatalog:
    catalog = PlanningCatalog.model_validate_json(_catalog_bytes())
    if any(
        b.fixture_id not in {f.id for f in fixture_manifest().fixtures} for b in catalog.bindings
    ):
        raise ValueError("planning binding references an unapproved fixture identity")
    return catalog


def create_plans(capture: Path, analysis: Path, correlation_file: Path) -> PlanningDocument:
    """Read local evidence only; a generated draft is neither authorization nor a verdict."""
    try:
        data = read_local(
            correlation_file.absolute().parent, correlation_file.name, MAX_DOCUMENT_BYTES
        )
        document = CorrelationDocument.model_validate_json(data)
        reconstructed = correlate(capture, analysis)
        if document != reconstructed:
            raise PlanningFailure(
                "correlation_mismatch", "Correlation does not reproduce from retained inputs"
            )
        catalog_bytes = _catalog_bytes()
        catalog = planning_catalog()
        if catalog != PlanningCatalog.model_validate_json(catalog_bytes):
            raise ValueError("planning catalog changed")
        fixture = admit_fixture(document.snapshot.fingerprint)
        binding = next((b for b in catalog.bindings if b.fixture_id == fixture.id), None)
        if binding is None:
            raise PlanningFailure(
                "unsupported_fixture", "No reviewed planning binding exists for this fixture"
            )
        entries: list[FindingPlan] = []
        for original in document.findings:
            finding_id = original.imported.finding.id
            blocked = block_reason(document, original)
            if blocked is not None:
                entries.append(
                    FindingPlan(
                        finding_id=finding_id,
                        disposition="blocked",
                        reasons=(
                            Reason(
                                code=blocked,
                                message="Correlation does not support automatic planning; "
                                "this is not an exploitability assessment",
                            ),
                        ),
                    )
                )
                continue
            candidate = original.candidates[0]
            entries.append(
                FindingPlan(
                    finding_id=finding_id,
                    disposition="draft",
                    reasons=(
                        Reason(
                            code="draft_only",
                            message="Reviewed fixture test design; unmet prerequisites remain",
                        ),
                    ),
                    plan=DraftPlan(
                        fixture_id=fixture.id,
                        template_id=catalog.template.id,
                        execution_policy_id=catalog.execution.id,
                        candidate_result_id=candidate.id,
                        path_ids=tuple(p.path.id for p in candidate.paths),
                        unmet_prerequisites=(
                            Reason(
                                code="scanner_source_unverified",
                                message="Scanner source association and rule definition remain unverified",
                            ),
                            Reason(
                                code="execution_authorization_required",
                                message="Explicit execution authorization and runner policy checks are required",
                            ),
                            Reason(
                                code="approved_image_required",
                                message="A separately prepared approved immutable image must be bound to execution",
                            ),
                            Reason(
                                code="runtime_oracle_required",
                                message="A trusted driver must implement the controls, fresh canary, and bounded observations",
                            ),
                        ),
                    ),
                )
            )
        if (
            read_local(
                correlation_file.absolute().parent, correlation_file.name, MAX_DOCUMENT_BYTES
            )
            != data
        ):
            raise ValueError("correlation changed during planning")
        report = PlanningDocument(
            schema_version="1.0",
            catalog_id=catalog.id,
            catalog_sha256=hashlib.sha256(catalog_bytes).hexdigest(),
            correlation_sha256=hashlib.sha256(data).hexdigest(),
            correlation=document,
            fixture=binding,
            template=catalog.template,
            execution_requirements=catalog.execution,
            findings=tuple(entries),
        )
        if len(report.model_dump_json(indent=2).encode("utf-8")) + 1 > MAX_DOCUMENT_BYTES:
            raise PlanningFailure("planning_limit", "Planning output exceeds 64 MiB")
        return report
    except PlanningFailure:
        raise
    except (ValueError, OSError, CorrelationFailure) as exc:
        raise PlanningFailure(
            "invalid_planning_input",
            "Evidence or packaged planning policy is unreadable, modified, or inconsistent",
        ) from exc
