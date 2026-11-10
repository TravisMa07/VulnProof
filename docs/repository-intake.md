# Repository SARIF intake

From an installed VulnProof checkout:

```sh
uv run --locked vulnproof intake --repo /path/to/checkout --sarif findings.sarif --output inventory.json
```

The new JSON file contains a version 1.0 repository inventory. Every embedded result array element gets an occurrence ID derived from the exact report SHA-256 and its run/result indexes, a pointer into the original SARIF, available normalized fields, and diagnostics. Identical results in one run link to their first occurrence. Suppressed results remain visible. A malformed result array has a null count and a run diagnostic. The top-level count covers readable arrays. Raw UTF-8 report text preserves additional locations, columns, scanner metadata and extensions exactly as supplied.

The default scope is the entire selected root. Only referenced regular files are read, once per resolved path, for a SHA-256 and line-range check. An optional `--component src/exports` limits source reads and marks other paths outside the component while retaining their occurrences. Safe relative URIs, logical %SRCROOT% paths, and in-run artifact indexes are supported. Unknown URI bases, absolute paths, conflicting references, symlinks, special files, and escapes produce explicit location states. External property documents are never fetched. File presence without a region establishes only existence. Reported revisions and optional local Git HEAD are observations. Scanner provenance remains unverified.

Intake accepts common embedded SARIF 2.1.0 fields across producer names. Direct rule identities and driver rule indexes are supported. Extension-specific references or unresolved messages stay in the raw report with diagnostics. The existing Semgrep ingestion and evidence contracts remain available for fixture validation.

Limits include 10 MiB input, 128 runs, 10,000 result occurrences, 50,000 locations, 8 MiB per referenced file and 64 MiB aggregate source reads. An oversized source read consumes its allowance. Intake uses the existing source exclusions and POSIX descriptor-relative filesystem policy. Output is bounded to 64 MiB and published exclusively. Exit 0 indicates complete accounting with resolved in-scope locations, 1 indicates a published partial inventory, and 2 indicates a rejected command with no new inventory. An import supplies no exploitability assessment or execution authorization.
