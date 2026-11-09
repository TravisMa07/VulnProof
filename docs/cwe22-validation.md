# Reviewed CWE-22 validation

Roadmap item 10b adds a `validate` command that reproduces a retained fixture plan,
executes a separately approved traversal driver, and publishes an existing
`EvidenceBundle` as `result.json`. It supports the two reviewed fixture identities;
there is no arbitrary repository, image, payload, command, or Docker-option input.

## Preparation and reproduction

Start with the [controlled scanner](controlled-scans.md), [CodeQL analysis](codeql-analysis.md),
and [planning](validation-plans.md) setup. Use Python 3.14.10 / uv 0.13.6. Native
Semgrep and CodeQL remain separately prepared tools. Fixture Flask dependencies,
base-image digest, and Python image pin remain those reviewed in PR 9.

Validation images have their own reviewed `vulnproof.validation/approvals.json` and
`fixture-cwe22-validation-v1` profile. Their narrow build context contains the fixed
validation driver, existing diagnostic driver, selected app, dependency lock, and
legitimate document. Preparation can download and build; validation cannot.

```sh
mkdir -p .cache
uv run --locked python scripts/prepare_validation_images.py \
  --docker-socket /var/run/docker.sock --output .cache/validation-preparation
uv run --locked python scripts/check_cwe22_validation.py \
  --docker-socket /var/run/docker.sock \
  --preparation .cache/validation-preparation/prepared-images.json
```

On Docker Desktop for macOS, select its absolute local Unix socket (commonly
`/Users/USERNAME/.docker/run/docker.sock`). Outputs must be new directories. Missing
tools, stale approvals, changed inputs, unavailable Docker, and unsupported daemon
capabilities fail explicitly.

The check script performs actual Semgrep scanning, source capture, CodeQL analysis,
correlation, planning, validation, and evidence assembly for the vulnerable fixture.
It requires `confirmed`, repeats validation without a supplied scan association to
require `inconclusive` despite observed disclosure, and checks that the two attempts
used different containers and fresh canary bytes. It then checks the patched driver independently with a
legitimate control and two 404 observations, without constructing a patched scanner
finding or emitting a patched assessment. These checks are not the expanded PR 12
benchmark or a broad coverage claim.

To validate an existing plan, select its occurrence ID:

```sh
uv run --locked vulnproof validate \
  --capture .cache/vulnerable-scan/capture/snapshot \
  --scan .cache/vulnerable-scan \
  --analysis .cache/vulnerable-analysis \
  --correlation .cache/correlation.json --plan .cache/plan.json \
  --preparation .cache/validation-preparation/prepared-images.json \
  --finding-id 'OCCURRENCE_ID_FROM_PLAN' \
  --docker-socket /var/run/docker.sock --output .cache/validation \
  --authorize-validation
```

If the unique candidate contains alternative paths, supply `--path-id` explicitly.
Ambiguous candidate groups remain blocked; selecting a path cannot bypass that
ambiguity. Omitting `--scan` preserves unknown scanner provenance even if a probe
observes disclosure. Diagnostics' `--authorize-execution` flag and preparation
receipts cannot authorize validation. This command requires `--authorize-validation`.
All input evidence remains unchanged.

## Driver and isolation

The existing runner's Docker client, image/container checks, fixed create arguments,
output budgets, signal-aware cleanup, and ownership labels are reused. The image is
selected by immutable ID from a validation preparation receipt, tied to the source
fingerprint and installed recipe. Preparation records assume a trusted local builder
and daemon; they are not signed image attestations.

Containers retain PR 9's non-root identity, read-only root, dropped capabilities,
no-new-privileges, no external network, no published ports, no host mounts, one CPU,
256 MiB memory (including swap), 64 processes, and 16 MiB temporary storage. The
attached execution deadline is 60 seconds; management and cleanup have their own
bounded deadlines. The entire attempt shares the runner's 1 MiB output budget,
including its reserved cleanup budget. Isolation checks do not prove immunity to
all container escapes. Container absence is checked after every creation attempt.

Inside each fresh container, the driver first runs the existing diagnostics. It
then starts Flask over loopback and verifies the legitimate document's exact hash.
Only after that control passes does it create a random filename exclusively under
`/tmp/vulnproof`, outside `/fixture/downloads`, containing a fresh 32-byte random
nonce encoded in a marker. It verifies the write, then performs parent traversal
and absolute-path probes with the fixed `name` query parameter. Redirects are not
followed. Each response is bounded to 64 KiB and three seconds. A positive oracle
requires status 200 and exact expected canary bytes; status alone, reflected input,
substrings, and a static canary never suffice. A bad control stops probes. Transport,
server, response-limit, and harness errors retain a failed partial driver report.

The fixture source is unchanged and is imported only inside the approved container.
The driver does not install dependencies, build repositories, read host secrets,
or contact arbitrary targets. Cleanup of the container also removes its temporary
canary. Hard process termination or daemon loss can prevent verified cleanup; the
reservation names the container for manual recovery.

## Results and limitations

- `confirmed`: verified controlled-scan association, compatible selected static path,
  matching source/image, valid control, exact fresh-canary disclosure, completed
  execution, intact retained evidence, and verified container absence.
- `inconclusive`: valid probes without disclosure, unverified scanner provenance,
  or insufficient/ambiguous modeled candidates. No safety conclusion follows.
- `unsupported`: a required finding mapping is outside the approved scope.
- `failed`: analysis, execution, policy, evidence integrity, or cleanup failure.
  A previously observed disclosure remains recorded even when a later failure
  prevents confirmation.

Invalid input/authorization errors reject the command before execution rather than
inventing an assessment for an unidentified finding. Blocked identified findings get
no execution. The command exits 0 for a produced non-failed classification, 1 for a
failed classification, 2 for rejected input, and 130 for interruption. Interruption
retains `attempt.json`, reservation, and a failed result when normal cleanup and
publication can complete. A second interruption or abrupt host/daemon failure can
still prevent publication.

`evidence/` retains bounded source/ingestion/provenance, plan, preparation, approval,
static evidence, controlled-scan proof when supplied, and the attempt record.
`diagnostics/` retains runner logs, referenced with hashes and truncation flags.
The JSON bundle keeps source state, static state, execution outcome, oracle, and
assessment separate. It does not rewrite original findings or draft plans. Retained
receipts and driver data come from a trusted local producer, not hostile-writer-proof
storage; artifact checking detects inconsistent edits, not coherent forgery.

The default test suite uses authored tool responses and requires no external tools.
A separate trusted same-repository/main CI job runs real tools and containers, with
read-only repository permissions and bounded diagnostic retention. HTML reports,
four-pair benchmarks, broader patterns, and CWE-78 remain later roadmap items.
