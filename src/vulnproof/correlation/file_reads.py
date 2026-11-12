"""Locate the first positional argument of direct Python open calls without importing source."""

import ast
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


def serving_arguments(root: Path, path: str, family: str) -> list[SourceLocation]:
    """Resolve bounded Flask import aliases conservatively; never execute source."""
    data = read_local(root, path, MAX_FILE_BYTES)
    if len(data) > 256 * 1024:
        return []
    try:
        source = data.decode(tokenize.detect_encoding(io.BytesIO(data).readline)[0])
        tree = ast.parse(source)
    except SyntaxError, UnicodeError, ValueError, RecursionError, LookupError:
        return []
    imports: dict[str, str] = {}
    duplicate = set()
    node: ast.AST
    for node in tree.body:
        pairs = []
        if isinstance(node, ast.ImportFrom) and node.module == "flask" and not node.level:
            pairs = [
                (a.asname or a.name, a.name)
                for a in node.names
                if a.name in ("send_file", "send_from_directory")
            ]
        elif isinstance(node, ast.Import):
            pairs = [(a.asname or a.name, "flask") for a in node.names if a.name == "flask"]
        for name, target in pairs:
            if name in imports:
                duplicate.add(name)
            imports[name] = target
    shadowed = {
        n.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))
    }
    shadowed.update(n.arg for n in ast.walk(tree) if isinstance(n, ast.arg))
    shadowed.update(
        n.name
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    all_bindings = [
        a.asname or a.name.split(".")[0]
        for n in ast.walk(tree)
        if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in n.names
    ]
    shadowed.update(name for name in imports if all_bindings.count(name) != 1)
    shadowed.update(duplicate)
    assigned_attributes = {
        (n.value.id, n.attr)
        for n in ast.walk(tree)
        if isinstance(n, ast.Attribute)
        and isinstance(n.value, ast.Name)
        and isinstance(n.ctx, (ast.Store, ast.Del))
    }
    lines = source.splitlines()
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        resolved = None
        if isinstance(function, ast.Name) and function.id not in shadowed:
            resolved = imports.get(function.id)
        elif isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
            if imports.get(function.value.id) == "flask" and function.value.id not in shadowed:
                # Any assignment to this attribute makes module API resolution uncertain.
                if (function.value.id, function.attr) not in assigned_attributes:
                    resolved = function.attr
        if resolved != family:
            continue
        index = 0 if family == "send_file" else 1
        keyword = "path_or_file" if family == "send_file" else "path"
        values = ([node.args[index]] if len(node.args) > index else []) + [
            kw.value for kw in node.keywords if kw.arg == keyword
        ]
        if (
            len(values) != 1
            or any(isinstance(a, ast.Starred) for a in node.args)
            or any(k.arg is None for k in node.keywords)
        ):
            continue
        value = values[0]
        if value.end_lineno is None or value.end_col_offset is None:
            continue

        def column(line: int, offset: int) -> int:
            return len(lines[line - 1].encode("utf-8")[:offset].decode("utf-8")) + 1

        found.append(
            SourceLocation(
                path=path,
                start_line=value.lineno,
                end_line=value.end_lineno,
                start_column=column(value.lineno, value.col_offset),
                end_column=column(value.end_lineno, value.end_col_offset),
            )
        )
    return found
