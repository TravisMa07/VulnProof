"""Prepare both outputs before exclusively creating a new report directory."""

import os
from collections.abc import Callable
from pathlib import Path

from vulnproof.provenance.filesystem import open_root

from .html import render_html
from .models import ReportDocument
from .prepare import ReportFailure, prepare_report

MAX_OUTPUT_BYTES = 64 * 1024 * 1024


def write_report(validation: Path, output: Path) -> ReportDocument:
    report = prepare_report(validation)
    publish_report(
        validation,
        output,
        lambda: {
            "report.json": (report.model_dump_json(indent=2) + "\n").encode("utf-8"),
            "report.html": render_html(report).encode("utf-8"),
        },
    )
    return report


def publish_report(validation: Path, output: Path, prepare: Callable[[], dict[str, bytes]]) -> None:
    try:
        validation, output = validation.absolute(), output.absolute()
        if output.resolve().is_relative_to(validation.resolve()):
            raise ReportFailure(
                "invalid_report_output", "Report output must be outside validation evidence"
            )
        with open_root(output.parent) as parent:
            if output.exists() or output.is_symlink():
                raise ReportFailure(
                    "report_output_exists", "Refusing to overwrite an existing report destination"
                )
            contents = prepare()
            if any(len(data) > MAX_OUTPUT_BYTES for data in contents.values()):
                raise ReportFailure(
                    "report_output_limit", "Rendered output exceeds 64 MiB per file"
                )
            os.mkdir(output.name, mode=0o700, dir_fd=parent)
            descriptor = os.open(
                output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
            created = []
            try:
                for name, data in contents.items():
                    file = os.open(
                        name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        mode=0o600,
                        dir_fd=descriptor,
                    )
                    created.append(name)
                    with os.fdopen(file, "wb") as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
            except BaseException:
                # Only remove files exclusively created by this invocation in the anchored directory.
                for name in created:
                    os.unlink(name, dir_fd=descriptor)
                os.rmdir(output.name, dir_fd=parent)
                raise
            finally:
                os.close(descriptor)
    except ReportFailure:
        raise
    except (ValueError, OSError) as exc:
        raise ReportFailure(
            "report_publication_failed", "Could not read inputs or publish new report files"
        ) from exc
