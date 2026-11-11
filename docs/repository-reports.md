# Repository evidence reports

`vulnproof report-repository` produces an offline repository inventory and per-finding
flows from retained evidence. It does not run scanners, Git, Docker, or applications.

```sh
uv run --locked vulnproof report-repository \
  --scan .cache/repository-scan \
  --investigation .cache/repository-investigation \
  --correlation .cache/repository-correlation.json \
  --discovery .cache/repository-discovery.json \
  --plan .cache/repository-plan.json \
  --config endpoints.json \
  --validation .cache/repository-validation-001 \
  --output .cache/repository-report-001
```

Supply the original configuration if planning used one. Omit `--validation` to report
before execution; repeat it to inspect separate attempts. Choose a new output directory
outside every input. Existing output is never overwritten. Open `report.html` locally;
`report.json` uses schema 1.0 and profile `repository-evidence-report-v1`.

## Interpretation

Every occurrence in the retained plan appears, including duplicates and unsupported
findings. The report shows modeled CodeQL locations and bounded source excerpts,
request bindings, planning gaps, and available container observations. Operator
origins, alternatives, and original scanner records remain in expandable details.
Modeled locations are not a trace of executed instructions.

Runtime flows show the legitimate control, file boundary, synthetic marker, exact
requests, response status and length, marker comparisons, execution, and cleanup.
Response bodies are not retained by repository validation; reports retain their
hashes and lengths. Each attempt keeps its original classification and reason.
Attempts are not combined into a new verdict. Imported scanner provenance stays
unverified even when a marker response was observed. “Not tested in this report”
means no result was supplied, not that no test occurred elsewhere. Unsuccessful
probes never establish safety.

## Integrity and boundaries

The reporter reconstructs planning from retained evidence and compares the supplied
plan. It checks result/plan/source identity, runtime path and request references,
the separate runtime record, classification consistency, and diagnostic hashes.
Contradictions preserve the recorded classification and add integrity warnings.
Missing or changed upstream evidence leaves the readable plan as the inventory,
with its associations explicitly labeled as retained claims. An invalid or unreadable
plan prevents publication. Unassociated and unreadable results appear separately.

Integrity checks local consistency, not producer authenticity. The report does not
inspect prepared images again or attest preparation receipts. Runtime image IDs and
preparation hashes remain recorded observations. The application and observer share
a container and UID; their observations are not attestations against hostile code.

Limits: 64 distinct validation directories; 10,000 planned occurrences; 64 MiB per
input; 128 MiB combined report-record, diagnostic, and excerpt reads; 256 inspected
diagnostic artifacts; previews of 16 KiB each and 256 KiB combined. Upstream
reconstruction retains its existing separate pipeline limits. Excerpts cover at most
128 files and 1,024 locations, with 1,600 characters each; omitted excerpts are
labeled. Each output is limited to 64 MiB. Symlinked evidence and non-regular files
are rejected. HTML is escaped and self-contained, with a restrictive content security
policy and no scripts or external resources.

Exit 0 means publication with verified inspected evidence; exit 1 means publication
with integrity warnings; exit 2 means invalid input/selection or publication failure.
These codes describe reporting, not the finding's classification.

## Next checkpoint

E3c is the [cross-repository demonstration](roadmap.md#cross-repository-checkpoint):
vulnerable and patched revisions, then a second compatible repository using the same
installed build. Reporting does not itself satisfy that checkpoint.
