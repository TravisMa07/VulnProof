"""Synthetic static-pipeline artifacts shared by correlation and planning tests."""

import json
import shutil
from pathlib import Path
from typing import Any

from vulnproof.correlation import policy
from vulnproof.ingest import ingest_sarif
from vulnproof.models import Reason, SourceBinding, ToolIdentity
from vulnproof.provenance import capture_source, verify_capture
from vulnproof.static.models import AnalysisDocument, CommandRecord
from vulnproof.static.process import artifact
from vulnproof.static.sarif import normalize_sarif

ROOT = Path(__file__).resolve().parents[1]


def location(line: int, *, uri: str = "app.py", **region: int) -> dict[str, Any]:
    names = {"start_column": "startColumn", "end_column": "endColumn", "end_line": "endLine"}
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": line, **{names.get(k, k): v for k, v in region.items()}},
        }
    }


def scanner_sarif(
    *,
    rule: str | None = None,
    line: int = 19,
    duplicates: int = 1,
    uri: str = "app.py",
    cwe: str = "CWE-22",
    **region: int,
) -> bytes:
    rule = rule or policy().rule_id
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Semgrep",
                            "version": "synthetic",
                            "rules": [{"id": rule, "properties": {"tags": [cwe]}}],
                        }
                    },
                    "results": [
                        {
                            "ruleId": rule,
                            "message": {"text": "Synthetic fixture finding"},
                            "locations": [location(line, uri=uri, **region)],
                        }
                        for _ in range(duplicates)
                    ],
                }
            ],
        }
    ).encode()


def codeql_sarif(
    *, results: int = 1, alternatives: int = 1, partial: bool = False, line: int = 19, **region: int
) -> bytes:
    flows = [
        {
            "locations": [
                {"location": location(14)},
                {"location": location(line, uri="app.py", **region)},
            ]
        }
        for _ in range(alternatives)
    ]
    if partial:
        flows.append({"locations": [{"location": location(14)}]})
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.27.3"}},
                    "results": [
                        {
                            "ruleId": "py/path-injection",
                            "locations": [location(line, uri="app.py", **region)],
                            "codeFlows": [{"threadFlows": flows}],
                        }
                        for _ in range(results)
                    ],
                }
            ],
        }
    ).encode()


def prepare(
    tmp_path: Path,
    scanner: bytes | None = None,
    raw: bytes | None = None,
    *,
    failed: bool = False,
    variant: str = "vulnerable",
) -> tuple[Path, Path]:
    source = tmp_path / "source"
    source.mkdir()
    shutil.copyfile(ROOT / "fixtures/cwe22" / variant / "app.py", source / "app.py")
    ingestion = tmp_path / "ingestion.json"
    ingestion.write_text(ingest_sarif(scanner or scanner_sarif()).model_dump_json())
    capture_source(ingestion, source, tmp_path / "capture")
    capture = tmp_path / "capture/snapshot"
    provenance = verify_capture(capture)
    analysis = tmp_path / "analysis"
    (analysis / "diagnostics").mkdir(parents=True)
    (analysis / "work").mkdir()
    shutil.copytree(capture / "source", analysis / "work/source")
    sarif_path = analysis / "diagnostics/raw.sarif"
    sarif_path.write_bytes(raw or codeql_sarif())
    results, notes = normalize_sarif(
        sarif_path.read_bytes(), analysis / "work/source", provenance.files
    )
    commands = []
    for stage in ("version", "extract", "query"):
        log = analysis / f"diagnostics/{stage}.log"
        log.write_text("Synthetic retained log\n")
        commands.append(
            CommandRecord.model_validate(
                {
                    "stage": stage,
                    "outcome": "completed",
                    "return_code": 0,
                    "duration_seconds": 0.0,
                    "log": artifact(log, analysis, f"log:{stage}"),
                }
            )
        )
    report = AnalysisDocument(
        schema_version="1.0",
        id="analysis:synthetic",
        fixture_id=f"cwe22-{variant}-v1",
        snapshot=provenance.snapshot,
        source=SourceBinding(
            expected_snapshot_id=provenance.snapshot.id,
            observed_snapshot_id=None if failed else provenance.snapshot.id,
            state="unverified" if failed else "matched",
            reason=Reason(code="synthetic", message="Synthetic source observation"),
        ),
        tool=ToolIdentity(
            name="CodeQL", version="2.27.3", rule_pack="codeql/python-queries@1.8.13"
        ),
        outcome="failed" if failed else "completed",
        normalization="not_attempted"
        if failed
        else ("partial" if notes or any(r.diagnostics for r in results) else "complete"),
        results=() if failed else results,
        commands=tuple(commands),
        raw_sarif=artifact(sarif_path, analysis, "sarif:raw"),
        diagnostics=(Reason(code="synthetic_failure", message="Synthetic failure"),)
        if failed
        else notes,
    )
    (analysis / "analysis.json").write_text(report.model_dump_json())
    return capture, analysis
