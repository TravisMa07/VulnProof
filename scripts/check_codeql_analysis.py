"""Real integration acceptance for the two approved captures; no fixture imports."""

import json
from pathlib import Path
from uuid import uuid4

from vulnproof.correlation import correlate, policy
from vulnproof.ingest import ingest_sarif
from vulnproof.provenance import capture_source
from vulnproof.static import analyze_capture

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    directory = ROOT / ".cache" / "analysis-check" / uuid4().hex
    directory.mkdir(parents=True)
    print(f"Artifacts: {directory}", flush=True)
    for variant in ("vulnerable", "patched"):
        # The scanner input is synthetic, not a Semgrep execution or provenance claim.
        # Only the vulnerable fixture has a synthetic finding; patched query observations
        # remain unconstrained rather than imposing an absence-of-findings gate.
        raw: dict[str, object] = {"version": "2.1.0", "runs": []}
        if variant == "vulnerable":
            source = (ROOT / "fixtures/cwe22/vulnerable/app.py").read_text().splitlines()
            sink_line = next(i for i, line in enumerate(source, 1) if "open(path," in line)
            raw["runs"] = [
                {
                    "tool": {
                        "driver": {
                            "name": "Semgrep",
                            "version": "synthetic",
                            "rules": [{"id": policy().rule_id, "properties": {"tags": ["CWE-22"]}}],
                        }
                    },
                    "results": [
                        {
                            "ruleId": policy().rule_id,
                            "message": {"text": "Synthetic correlation acceptance input"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": sink_line},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        scanner_bytes = json.dumps(raw).encode()
        (directory / f"{variant}-synthetic.sarif").write_bytes(scanner_bytes)
        document = ingest_sarif(scanner_bytes)
        ingestion = directory / f"{variant}-ingestion.json"
        ingestion.write_text(document.model_dump_json())
        capture = directory / f"{variant}-capture"
        capture_source(ingestion, ROOT / "fixtures" / "cwe22" / variant, capture)
        report = analyze_capture(
            capture / "snapshot",
            directory / f"{variant}-analysis",
            ROOT / ".cache/codeql/2.27.3/codeql",
        )
        # Retain the report for CI even when an acceptance gate fails.
        (directory / f"{variant}-analysis/diagnostics/analysis.json").write_text(
            report.model_dump_json(indent=2)
        )
        if report.outcome != "completed" or report.normalization != "complete":
            raise SystemExit(f"FAIL {variant}: see retained analysis report")
        correlation = correlate(capture / "snapshot", directory / f"{variant}-analysis")
        (directory / f"{variant}-analysis/diagnostics/correlation.json").write_text(
            correlation.model_dump_json(indent=2)
        )
        paths = [p.path for result in report.results for p in result.paths]
        if variant == "vulnerable":
            # Fixture-specific acceptance only, never a general engine correlation rule.
            source = (capture / "snapshot/source/app.py").read_text().splitlines()
            input_line = next(i for i, line in enumerate(source, 1) if "request.args.get" in line)
            sink_line = next(i for i, line in enumerate(source, 1) if "open(path," in line)
            if not any(
                any(loc.start_line == input_line for loc in p.locations[:-1])
                and p.locations[-1].start_line == sink_line
                for p in paths
            ):
                raise SystemExit("FAIL vulnerable: no complete request-to-open path")
            if (
                correlation.findings[0].status != "single_candidate"
                or correlation.findings[0].imported.finding.source.state != "unverified"
            ):
                raise SystemExit("FAIL vulnerable: expected an unverified-source candidate")
        print(
            f"PASS {variant}: {len(report.results)} result(s), {len(paths)} path(s); observations retained",
            flush=True,
        )
        # CI artifacts contain only bounded report/log/SARIF copies, never databases.
    print(json.dumps({"status": "passed", "artifacts": str(directory)}))


if __name__ == "__main__":
    main()
