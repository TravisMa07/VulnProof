# Contributing to VulnProof

VulnProof is being built one reviewable roadmap item at a time. Discuss the design and
acceptance criteria before implementation. Complete review and obtain the project
owner's explicit merge authorization before starting the next item. Follow the
[implementation roadmap](docs/roadmap.md) for the agreed PR sequence.

## Development environment

The initial supported development runtime is CPython 3.14.10. The package declares
Python 3.14 support only; expand it when other versions have been tested. CI runs
on Ubuntu 24.04; local development is also verified on macOS. Fixture execution
and Docker support will be established separately in the feasibility work.

Python 3.14 provides a maintained baseline within CodeQL's documented Python
analysis support. The interpreter used by VulnProof does not need to match every
fixture's interpreter. Pinning a patch release keeps development and CI consistent;
review and test patch updates rather than leaving the pin unchanged indefinitely.
See the [Python support table](https://devguide.python.org/versions/) and
[CodeQL support matrix](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/).

Install [uv 0.13.6](https://docs.astral.sh/uv/getting-started/installation/), clone
the repository, and run from its root:

```sh
uv python install
uv sync --locked
```

`uv sync` installs VulnProof as an editable package plus the locked development
tools. Commit `uv.lock`; use `--locked` to detect unintended dependency changes.
The Python version is recorded in `.python-version`. Add runtime dependencies
only when the feature using them is introduced.

The initial tools are Ruff for formatting and linting, mypy for strict type
checking, pytest for behavior tests, and Hatchling for packaging. There is no
application CLI yet.

## Required checks

Run the same checks locally as CI:

```sh
uv run --locked ruff format --check .
uv run --locked ruff check .
uv run --locked mypy
uv run --locked pytest
uv build
uv run --isolated --no-project --python 3.14.10 --with dist/*.whl python -I -c "import vulnproof; from importlib.metadata import version; print(version('vulnproof'))"
```

To format code while developing, run `uv run --locked ruff format .`. Review
any lint fixes before committing. Tests use the installed package rather than
adding the source directory to the import path. The isolated wheel check verifies
that packaging works without the editable installation. Keep only the current
wheel in `dist/` when running that check.

For intentional dependency updates, edit the relevant version, run `uv lock`,
then `uv sync --locked` and all checks. Review the lockfile diff. Build-backend
and development-tool versions are pinned; CI actions are pinned by commit SHA.
Update pins with their corresponding documentation and version comments.

## Code and tests

- Use typed boundaries, explicit errors, and small modules with clear responsibilities.
- Keep scanner adapters, execution policy, and evidence classification separate.
- Version persisted artifacts when those contracts are introduced.
- Test observable behavior, failure cases, and security boundaries. Avoid tests
  that merely repeat implementation details or arbitrary coverage targets.
- Use unit tests for logic, integration tests for tool boundaries, and isolated
  execution tests for runtime restrictions as those features become available.
- Preserve uncertainty: unsuccessful tests never prove safety.
- Never execute arbitrary repositories or introduce unreviewed fixture execution.
- Document public behavior and material limitations in the same PR as the change.

## Branches, commits, and review

1. Start a descriptive branch from current `main`, such as
   `chore/development-foundation` or `feat/sarif-ingestion`.
2. Agree on the behavior, tradeoffs, interfaces, and acceptance criteria.
3. Make small coherent commits using Conventional Commit prefixes: `feat:`,
   `fix:`, `test:`, `docs:`, or `chore:`. Do not combine unrelated changes.
4. Run the relevant checks and inspect the diff for secrets or generated files.
5. Open a PR against `main` using the PR template. Explain the problem, resulting
   behavior, validation actually performed, and material risks or limitations.
6. Address review feedback and obtain explicit merge authorization from the
   project owner. Do not merge automatically or work directly on `main`.

The CI job is named **Development checks**. Repository administrators can require
it through branch protection. This workflow does not configure branch protection
or make a successful CI run a substitute for merge authorization.

## Owner review and design discussion

The project owner must have the opportunity to review the complete diff for every
change, including code, tests, configuration, workflows, documentation, and
dependency updates. A summary or passing checks do not replace this review.

- Provide the PR diff, or the complete local diff when a PR is not yet available.
  Include newly added files as well as changes to existing files.
- Offer a walkthrough that connects each part of the change to its purpose.
  Explain significant choices, alternatives considered, tradeoffs, and limitations
  in enough detail for the owner to evaluate and challenge them.
- Treat questions and requests for reasoning as part of review, not as approval.
  The owner may question any line, propose an alternative, or request changes.
- Discuss feedback and revise the implementation when needed. Explain any
  disagreement with concrete reasoning; do not silently dismiss feedback.
- After revisions, identify what changed, provide the updated diff, and rerun
  relevant checks. Resolve outstanding questions and requested changes with the
  owner before requesting merge authorization.
- Merge only after explicit authorization for the current revision. Further
  changes require renewed review and authorization. Silence, an explanation being
  accepted, or successful CI does not authorize merging.

Keep PRs small enough for this process to be practical. Do not start the next
roadmap item while the current change is awaiting review or merge authorization.
