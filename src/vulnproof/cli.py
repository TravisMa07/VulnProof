"""Local file IO and command presentation; ingestion itself has no IO."""

import argparse
import json
import os
import stat
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from .ingest import ImportFailure, ingest_sarif
from .ingest.sarif import MAX_INPUT_BYTES
from .provenance import CaptureFailure, capture_source, verify_capture


def _read_input(path: Path) -> bytes:
    # Nonblocking open lets us reject FIFOs/devices instead of waiting for a writer.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ImportFailure("invalid_input_file", "SARIF input must be a regular file")
        return stream.read(MAX_INPUT_BYTES + 1)


def _publish(path: Path, content: str) -> None:
    """Publish one complete file with no overwrite, including competing writers."""
    descriptor, temporary = tempfile.mkstemp(prefix=".vulnproof-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        # Same-directory hard link is atomic and fails if any destination exists.
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnproof", description="Investigate scanner findings")
    commands = parser.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser("ingest", help="Import local Semgrep SARIF 2.1.0")
    ingest.add_argument(
        "--sarif", type=Path, required=True, help="Existing SARIF file (10 MiB max)"
    )
    ingest.add_argument("--output", type=Path, required=True, help="New self-contained JSON file")
    capture = commands.add_parser(
        "capture", help="Capture bounded source with unverified scanner provenance"
    )
    capture.add_argument("--ingestion", type=Path, required=True)
    capture.add_argument("--source-root", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True, help="New directory outside source")
    capture.add_argument(
        "--expected-commit", help="Require the captured scope to match this full commit ID"
    )
    verify = commands.add_parser("verify-source", help="Rehash an existing capture before using it")
    verify.add_argument(
        "--capture", type=Path, required=True, help="Published output/snapshot directory"
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-source":
            provenance = verify_capture(args.capture)
            print(json.dumps({"status": "content_verified", "snapshot": provenance.snapshot.id}))
            return 0
        if args.command == "capture":
            provenance = capture_source(
                args.ingestion, args.source_root, args.output, expected_commit=args.expected_commit
            )
            partial = any(b.location != "present" for b in provenance.bindings) or any(
                d.code == "ingestion_partial" for d in provenance.diagnostics
            )
            for reason in provenance.diagnostics:
                print(f"{reason.code}: {reason.message}", file=sys.stderr)
            for binding in provenance.bindings:
                for reason in binding.reasons:
                    print(f"{reason.code}: {reason.message}", file=sys.stderr)
            print(
                json.dumps(
                    {
                        "status": "partial" if partial else "complete",
                        "snapshot": provenance.snapshot.id,
                        "files": len(provenance.files),
                        "unverified_bindings": len(provenance.bindings),
                    }
                )
            )
            return 1 if partial else 0
        document = ingest_sarif(_read_input(args.sarif))
        _publish(args.output, document.model_dump_json(indent=2) + "\n")
    except (ImportFailure, CaptureFailure) as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 2
    except FileExistsError:
        print("output_exists: Refusing to overwrite an existing output", file=sys.stderr)
        return 2
    except OSError as exc:
        # Do not echo untrusted paths/control characters from OS exception messages.
        print(
            f"file_error: Unable to read input or publish output (errno {exc.errno})",
            file=sys.stderr,
        )
        return 2
    for diagnostic in document.diagnostics:
        print(
            f"{diagnostic.severity}: {diagnostic.code} {diagnostic.pointer}: {diagnostic.message}",
            file=sys.stderr,
        )
    print(
        json.dumps(
            {
                "status": document.status,
                "imported": len(document.findings),
                "results": document.result_count,
                "diagnostics": len(document.diagnostics),
            }
        )
    )
    return 1 if document.status == "partial" else 0
