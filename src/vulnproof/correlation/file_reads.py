"""Locate the first positional argument of direct Python open calls without importing source."""

import io
import tokenize
from pathlib import Path

from vulnproof.artifacts import read_local
from vulnproof.models import SourceLocation
from vulnproof.provenance.models import MAX_FILE_BYTES


def arguments(root: Path, path: str) -> list[SourceLocation]:
    data = read_local(root, path, MAX_FILE_BYTES)
    found: list[SourceLocation] = []
    depth = 0
    waiting = False
    previous = ""
    active: dict[int, tuple[int, int] | None] = {}
    end = (0, 0)
    try:
        for tok in tokenize.tokenize(io.BytesIO(data).readline):
            if tok.type in (tokenize.COMMENT, tokenize.NL, tokenize.ENCODING):
                continue
            boundary = tok.type == tokenize.OP and tok.string in (",", ")")
            if depth in active:
                start = active[depth]
                if boundary:
                    del active[depth]
                    if start:
                        found.append(
                            SourceLocation(
                                path=path,
                                start_line=start[0],
                                start_column=start[1] + 1,
                                end_line=end[0],
                                end_column=end[1] + 1,
                            )
                        )
                elif start is None:
                    active[depth] = tok.start
            if tok.type == tokenize.OP and tok.string in ("(", "[", "{"):
                depth += 1
                if waiting and tok.string == "(":
                    active[depth] = None
            elif tok.type == tokenize.OP and tok.string in (")", "]", "}"):
                depth -= 1
            waiting = tok.type == tokenize.NAME and tok.string == "open" and previous != "."
            previous = tok.string
            end = tok.end
    except SyntaxError, tokenize.TokenError, UnicodeError:
        return []
    return found


def overlaps(a: SourceLocation, b: SourceLocation) -> bool:
    """Compare half-open ranges, including the boundary lines of multiline arguments."""
    return a.path == b.path and (
        (a.start_line, a.start_column or 1)
        < (b.end_line or b.start_line, b.end_column or float("inf"))
        and (b.start_line, b.start_column or 1)
        < (a.end_line or a.start_line, a.end_column or float("inf"))
    )


def same_argument(argument: SourceLocation, sink: SourceLocation) -> bool:
    """Avoid attaching nested or adjacent path operations to the enclosing open call."""
    return (
        argument.path == sink.path
        and argument.start_line == sink.start_line
        and argument.end_line == (sink.end_line or sink.start_line)
        and sink.start_column == argument.start_column
        and sink.end_column == argument.end_column
    )
