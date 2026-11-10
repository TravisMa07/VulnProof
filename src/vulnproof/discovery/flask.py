"""Read direct Flask declarations as source data. Never import a captured module."""

import ast
import io
import tokenize
from dataclasses import dataclass

from vulnproof.models import SourceLocation


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    evidence: SourceLocation


@dataclass
class Handler:
    name: str
    location: SourceLocation
    application: str | None
    declaration: SourceLocation | None
    routes: list[Route]
    inputs: list[tuple[str, SourceLocation]]
    gaps: list[str]
    nested_scopes: list[tuple[int, int]]


def literal(node: ast.expr) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


@dataclass
class Module:
    handlers: list[Handler]
    request_import_lines: set[int]
    issue: str | None = None


def parse_module(path: str, data: bytes) -> Module:
    if len(data) > 256 * 1024:
        return Module([], set(), "module_size_limit")
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        source = data.decode(encoding).replace("\r\n", "\n").replace("\r", "\n")
        # Limit compiler recursion on adversarial expression chains before constructing an AST.
        expression_tokens = 0
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            expression_tokens = 0 if token.type == tokenize.NEWLINE else expression_tokens + 1
            if expression_tokens > 512:
                return Module([], set(), "module_complexity_limit")
        lines = source.split("\n")
        module = ast.parse(source)
    except SyntaxError, UnicodeError, ValueError, RecursionError, LookupError, tokenize.TokenError:
        return Module([], set(), "module_unreadable")

    def span(node: ast.expr | ast.stmt) -> SourceLocation:
        end = node.end_lineno or node.lineno

        def column(line: int, offset: int) -> int:
            return len(lines[line - 1].encode()[:offset].decode()) + 1

        return SourceLocation(
            path=path,
            start_line=node.lineno,
            end_line=end,
            start_column=column(node.lineno, node.col_offset),
            end_column=column(end, node.end_col_offset)
            if node.end_col_offset is not None
            else None,
        )

    imports: dict[str, str] = {}
    apps: dict[str, SourceLocation] = {}
    handlers = []
    request_import_lines: set[int] = set()
    # A reassigned declaration cannot identify one stable application or import.
    stores: dict[str, int] = {}
    for node in ast.walk(module):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            stores[node.id] = stores.get(node.id, 0) + 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            stores[node.name] = stores.get(node.name, 0) + 1
        elif isinstance(node, ast.alias):
            name = node.asname or node.name
            stores[name] = stores.get(name, 0) + 1
    for statement in module.body:
        if (
            isinstance(statement, ast.ImportFrom)
            and statement.module == "flask"
            and not statement.level
        ):
            if any(a.name == "request" for a in statement.names):
                request_import_lines.update(
                    range(statement.lineno, (statement.end_lineno or statement.lineno) + 1)
                )
            imports.update(
                {
                    a.asname or a.name: a.name
                    for a in statement.names
                    if stores.get(a.asname or a.name) == 1
                }
            )
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            value = statement.value
            name = statement.targets[0].id
            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and imports.get(value.func.id) == "Flask"
                and stores.get(name) == 1
            ):
                apps[name] = span(statement)
        if (
            not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            or not statement.decorator_list
        ):
            continue
        shadowed = {a.arg for a in ast.walk(statement.args) if isinstance(a, ast.arg)}
        inputs = []
        nested_scopes = []
        pending: list[ast.AST] = list(statement.body)
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                nested_scopes.append((node.lineno, node.end_lineno or node.lineno))
                continue
            pending.extend(ast.iter_child_nodes(node))
            if (
                not isinstance(node, ast.Call)
                or not isinstance(node.func, ast.Attribute)
                or node.func.attr != "get"
                or not node.args
            ):
                continue
            lookup = node.func.value
            if (
                isinstance(lookup, ast.Attribute)
                and lookup.attr == "args"
                and isinstance(lookup.value, ast.Name)
                and imports.get(lookup.value.id) == "request"
                and lookup.value.id not in shadowed
            ):
                key = literal(node.args[0])
                if key:
                    inputs.append((key, span(node)))
        for dec in statement.decorator_list:
            if (
                not isinstance(dec, ast.Call)
                or not isinstance(dec.func, ast.Attribute)
                or dec.func.attr not in ("get", "post", "put", "patch", "delete", "route")
            ):
                continue
            owner = dec.func.value
            app = owner.id if isinstance(owner, ast.Name) and owner.id in apps else None
            route = literal(dec.args[0]) if len(dec.args) == 1 else None
            methods = [dec.func.attr.upper()] if dec.func.attr != "route" else ["GET"]
            for kw in dec.keywords:
                if (
                    kw.arg == "methods"
                    and dec.func.attr == "route"
                    and isinstance(kw.value, (ast.List, ast.Tuple))
                ):
                    methods = [literal(v) or "" for v in kw.value.elts]
                    if not all(m.isascii() and m.isalpha() for m in methods):
                        methods = []
                else:
                    methods = []
                    break
            gaps = []
            if app is None:
                gaps.append("application_registration_unresolved")
            if not route or not route.startswith("/") or "<" in route:
                gaps.append("route_unresolved")
            if not methods:
                gaps.append("http_method_unresolved")
            routes = (
                [Route(m.upper(), route, span(dec)) for m in methods]
                if route and "route_unresolved" not in gaps
                else []
            )
            handlers.append(
                Handler(
                    statement.name,
                    span(statement),
                    app,
                    apps.get(app) if app else None,
                    routes,
                    inputs,
                    gaps,
                    nested_scopes,
                )
            )
    return Module(handlers, request_import_lines)
