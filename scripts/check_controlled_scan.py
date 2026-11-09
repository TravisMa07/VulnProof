"""Real Semgrep-to-CodeQL acceptance on the two reviewed fixtures; no app execution."""

from pathlib import Path
from uuid import uuid4

from vulnproof.correlation import correlate
from vulnproof.scanning import scan_fixture, verify_scan
from vulnproof.static import analyze_capture

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    directory = ROOT / ".cache/controlled-scan-check" / uuid4().hex
    directory.mkdir(parents=True)
    print(f"Artifacts: {directory}", flush=True)
    for variant in ("vulnerable", "patched"):
        scan = directory / f"{variant}-scan"
        receipt = scan_fixture(
            ROOT / "fixtures/cwe22" / variant, scan, ROOT / ".cache/semgrep/1.184.0"
        )
        if receipt.outcome != "completed":
            raise SystemExit(f"FAIL {variant}: scanner did not complete; see scan.json")
        association = verify_scan(scan)
        (scan / "diagnostics/association.json").write_text(association.model_dump_json(indent=2))
        analysis = directory / f"{variant}-analysis"
        report = analyze_capture(
            scan / "capture/snapshot", analysis, ROOT / ".cache/codeql/2.27.3/codeql"
        )
        (analysis / "diagnostics/analysis.json").write_text(report.model_dump_json(indent=2))
        if report.outcome != "completed" or report.normalization != "complete":
            raise SystemExit(f"FAIL {variant}: CodeQL analysis incomplete")
        correlation = correlate(scan / "capture/snapshot", analysis)
        (analysis / "diagnostics/correlation.json").write_text(
            correlation.model_dump_json(indent=2)
        )
        if report.snapshot != association.snapshot:
            raise SystemExit("FAIL: analysis and scanner source identities differ")
        if variant == "vulnerable" and (
            len(association.findings) != 1
            or len(correlation.findings) != 1
            or correlation.findings[0].status != "single_candidate"
            or correlation.findings[0].imported.finding != association.findings[0].original
        ):
            raise SystemExit("FAIL vulnerable: real finding has no unique compatible path")
        if any(f.imported.finding.source.state != "unverified" for f in correlation.findings):
            raise SystemExit("FAIL: original correlation records were upgraded")
        # Patched scanner/query results remain observations, with no absence gate.
        print(
            f"PASS {variant}: {len(association.findings)} real finding(s); source association verified",
            flush=True,
        )


if __name__ == "__main__":
    main()
