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
    args = parser.parse_args(argv)
    try:
        document = ingest_sarif(_read_input(args.sarif))
        _publish(args.output, document.model_dump_json(indent=2) + "\n")
    except ImportFailure as exc:
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
