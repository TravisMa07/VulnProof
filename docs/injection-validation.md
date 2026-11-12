# Command, SQL and template injection

Completion-roadmap PR 3 adds three **bounded** capabilities. It reuses the application
onboarding plan, immutable images, separate observer, admission gates and cleanup
policy. Application-specific facts stay in configuration; the engine has no benchmark
repository names or file paths. The existing CWE-22 workflow remains available.

## Support and evidence

| Capability / validator | Scanner rule suffix | Pinned official CodeQL query | Demonstrated behavior |
| --- | --- | --- | --- |
| Command / `command-injection-v1` (CWE-78) | `command-injection` | `py/command-line-injection` | POSIX shell input reflected through captured command output in an HTTP response. |
| SQL / `sql-injection-v1` (CWE-89) | `sql-injection` | `py/sql-injection` | Single-quoted SQLite SELECT value, with a fresh marker in an explicitly synthetic database row. |
| Template / `template-injection-v1` (CWE-1336; query tagged CWE-74) | `template-injection` | `py/template-injection` | Jinja string-expression evaluation through Flask `render_template_string`. |

Rule IDs are prefixed `vulnproof.repository.`. The controlled Semgrep scan runs the
installed rules, including the existing traversal rules. Reviewed mappings are in
`investigation/capabilities.py`; external SARIF rule names are not guessed into these
mappings. Other findings remain in the inventory with an explicit stopping reason.

Initial source bindings use direct Flask GET routes and literal `request.args.get`
keys. Planning requires one compatible sink result and a complete modeled path
containing the selected handler's observed query input. It accounts for every SARIF
occurrence, including duplicates. Several paths can support one request; competing
sink results remain ambiguous. Configuration cannot manufacture reachability or fill
an unsupported handler binding. Dynamic registration, path parameters, POST/body
sources, blind injection, other SQL dialects and other template engines are outside
these demonstrated profiles. General onboarding HTTP methods do not imply that a
validator supports those input locations.

CodeQL remains 2.27.3 with bundled `codeql/python-queries@1.8.13`. Each query file's
SHA-256 is fixed in the installed registry; arbitrary query paths are not accepted.
The official queries were exercised without custom source, sink or sanitizer models.
See [CodeQL prerequisites](codeql-analysis.md) for installation/licensing and analysis
limitations. Python, Flask and fixture dependency pins are unchanged from
[application onboarding](application-onboarding.md).

## Workflow

Start with `vulnproof scan` or `prepare-repository` and an immutable retained source
capture. Component selection remains optional. For each capability to investigate:

```sh
uv run --locked vulnproof investigate --scan /evidence/scan \
  --codeql-bundle /tools/codeql --capability command --output /evidence/command
uv run --locked vulnproof investigate --scan /evidence/scan \
  --codeql-bundle /tools/codeql --capability sql --output /evidence/sql
uv run --locked vulnproof investigate --scan /evidence/scan \
  --codeql-bundle /tools/codeql --capability template --output /evidence/template

uv run --locked vulnproof plan-injections --scan /evidence/scan \
  --investigation /evidence/command --investigation /evidence/sql \
  --investigation /evidence/template --config injection-endpoints.json \
  --output /evidence/injection-plans.json
```

Omitting `--config` still produces dispositions. Supplying only some investigations
keeps the other occurrences with `analysis_missing`. Failed or partial scans/analyses
cannot supply confirmation evidence. Input, log, inventory, source and normalized-path
edits are rejected. Use a new output outside all retained inputs.

Example endpoint configuration, schema 1.0:

```json
{
  "schema_version": "1.0",
  "endpoints": [{
    "capability": "command",
    "file": "app.py",
    "handler": "exercise",
    "request": {
      "schema_version": "1.0",
      "route": "/test",
      "query_key": "value",
      "fixed_query": [],
      "control_value": "reader"
    },
    "control_sha256": "3d0941964aa3ebdcb00ccef58b1bb399f9f898465e9886d5aec7f31090a0fb30",
    "synthetic_sql_state": false
  }]
}
```

The control expects HTTP 200 and exactly the SHA-256 of `reader`. Fixed parameters
are ordered and preserved; duplicate/conflicting parameters are rejected. This
configuration selects a discovered handler independently of scanner occurrence IDs.
Route/input declarations must agree with source observations. Preparation/startup
configuration is a separate [application profile](application-onboarding.md).

Review and authorize its preparation using `prepare-application`, then validate one
draft occurrence from `injection-plans.json`:

```sh
uv run --locked vulnproof validate-injection --scan /evidence/scan \
  --investigation /evidence/command --investigation /evidence/sql \
  --investigation /evidence/template --config injection-endpoints.json \
  --plan /evidence/injection-plans.json --finding-id OCCURRENCE_ID \
  --onboarding /evidence/onboarding.json --application-config application.json \
  --preparation /evidence/prepared/prepared-application.json \
  --docker-socket /var/run/docker.sock --output /evidence/attempt \
  --authorize-validation

uv run --locked vulnproof report-injections --scan /evidence/scan \
  --investigation /evidence/command --investigation /evidence/sql \
  --investigation /evidence/template --config injection-endpoints.json \
  --plan /evidence/injection-plans.json --validation /evidence/attempt \
  --output /evidence/report
```

Repeat `--validation` for other findings. Select one attempt per occurrence explicitly;
contradictory or repeated attempts are not silently merged. Reports include every
occurrence, modeled path locations/source snippets, exact control/probe targets,
marker observations, provenance, stopping reasons and stage counts. Rendering needs
neither Docker nor application imports. Untrusted values are escaped, and the HTML
has no external scripts, fonts or network dependencies. Reports reconstruct plans,
reassess observations and compare completed attempts with retained Docker inspection,
observer and cleanup transcripts. Modified or contradictory evidence fails reporting.

These are separate capability commands while the legacy traversal workflow remains
available. The unified resumable cross-class command and consolidated report are PR 7.

## Oracle and execution boundaries

Every attempt uses the existing restricted target and independent observer containers.
No host mounts, published ports, extra privileges, external egress or dependency
installation are introduced. Runtime/resource/output/cleanup limits from
[onboarding](application-onboarding.md#execution-boundaries-and-evidence) apply.
The installed observer generates at most two fixed probes. Application controls and
the selected endpoint's exact control must pass before probing.

- **Command:** a fixed shell `printf` expression computes a fresh nonce-bearing marker
  from separate quoted pieces. The full marker is absent from request text. Confirmation
  requires that marker in a successful HTTP response. This does not test arbitrary
  commands, blind side effects, Windows shells or out-of-band command execution.
- **SQL:** the operator declares `synthetic_sql_state: true`. A reviewed initializer
  must read `VULNPROOF_VALIDATION_MARKER` and insert that fresh synthetic value into a
  row unavailable through the legitimate request. The runner supplies the variable
  only for a validation attempt. A false predicate must return an empty response with
  HTTP 200 and no marker; failure stops before the positive predicate. Confirmation
  requires retrieval of the marker through the positive predicate. This is a synthetic
  data oracle, not an authorization-policy verdict or permission to access real data.
- **Template:** a fixed Jinja concatenation expression computes the fresh marker. The
  full expected marker is absent from the request, so literal reflection is insufficient.
  This observes expression evaluation; it does not run template-based system commands.

The observer retains response hashes, bounded lengths and marker presence, rather
than whole response bodies. Response processing stays within the existing limits.
The host verifies probe identity, targets, selected parameter, fixed parameters,
request-body/header hashes, control digest, nonce, sequence and truncation state.
Missing or inconsistent observations cannot confirm. Application code and configured
initializers execute only inside containers, including database creation.

Configuration declares how the application is deployed and which synthetic SQL row
is outside the legitimate lookup. Matching static and HTTP evidence does not attest
that every modeled intermediate statement executed. The operator trusts the local
Docker daemon, preparation receipts and reviewed dependencies. Local hashes detect
inconsistent artifacts; they are not signatures against an adversary who rewrites
all evidence. A failed negative egress probe is not proof against every network or
kernel escape.

`confirmed` requires the bounded positive observation, verified execution/cleanup,
passing controls and controlled scanner/source provenance. Imported SARIF retains
revision uncertainty, so otherwise positive evidence remains `inconclusive`.
Missing paths, competing sinks and unsuccessful probes are `inconclusive`, never safe.
Unsupported scanner/rule or invocation/configuration gaps remain `unsupported`.
Operational/control/cleanup failures are `failed`. Plans distinguish blocked from
executable drafts before any test. Exit 1 means a retained failed validation; exit 2
means rejected inputs/prerequisites; interruption exits 130 after cleanup/publication
when possible. Other conclusions exit 0, which is not a safety verdict.

Worker changes invalidate earlier preparation receipts: rebuild images before new
execution. Existing result schema 1.0 remains readable; validation attempts use
application-exercise schema 1.1 with an explicit validation request. Historical CWE-22
reports retain their original semantics and commands.

## Reproducible benchmark

`fixtures/injections` contains separate vulnerable/patched applications for each
capability. They use synthetic data only. No fixture module is imported on the host.
The paired fixes are argv-based command invocation, parameterized SQL and a constant
template with a data variable. The legitimate response stays the same.

Prepare CodeQL, Semgrep and the pinned Linux Flask wheelhouse following the existing
setup guides, then inspect the fixtures and run:

```sh
uv run --locked python scripts/check_injection_benchmark.py \
  --fixtures fixtures/injections --semgrep-environment .cache/semgrep/1.184.0 \
  --codeql-bundle .cache/codeql/2.27.3/codeql \
  --wheelhouse .cache/repository-control-wheels \
  --docker-socket /var/run/docker.sock --output /tmp/vulnproof-injection-benchmark \
  --authorize-preparation --authorize-validation
```

Use `$HOME/.docker/run/docker.sock` on Docker Desktop. Default is three fresh runs per
variant (18 attempts); `--runs 1` is an explicit faster diagnostic. The script scans
one copied benchmark checkout, analyzes it with each official query, requires a
source-bound vulnerable draft and runs through the same installed engine for every
case. It publishes `benchmark.json`, per-attempt evidence and an offline report.

The measured baseline is one vulnerable/patched pair per capability, not broad CWE
coverage. Actual Semgrep and CodeQL produced three vulnerable findings/paths and no
patched findings/paths. All nine vulnerable attempts confirmed; all nine patched
dynamic oracle attempts remained inconclusive with zero confirmations. Every attempt
verified cleanup. Patched cases without static findings are explicitly labeled
`dynamic_oracle_regression_not_finding_confirmation`; no SAST result or path is
invented to run them. Benchmark labels stay separate from engine conclusions.
The same gate must pass on the installed wheel before delivery. CI runs the benchmark
only for trusted same-repository PRs and main pushes, with read-only permissions.
