"""Python AST helpers: FastAPI routes and their Depends, function source, call sites."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from fnmatch import fnmatch

from secagent.context.redact import redact
from secagent.tools.fs import RepoFS, ToolError, wrap_untrusted

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)


@dataclass
class Route:
    method: str
    path: str
    function: str
    file: str
    line: int
    dependencies: list[str]
    params: list[str]


def _parse(fs: RepoFS, rel: str) -> ast.Module | None:
    try:
        return ast.parse("\n".join(fs.lines(rel)) + "\n", filename=rel)
    except (SyntaxError, ValueError, ToolError):
        return None


def _python_files(fs: RepoFS, glob: str) -> list[str]:
    return [f for f in fs.files() if f.endswith(".py") and fnmatch(f, glob)]


def _depends_target(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
    if name != "Depends":
        return None
    return ast.unparse(node.args[0]) if node.args else "Depends()"


def _param_defaults(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST]:
    return [*fn.args.defaults, *(d for d in fn.args.kw_defaults if d is not None)]


def _route(fn: ast.FunctionDef | ast.AsyncFunctionDef, dec: ast.expr, rel: str) -> Route | None:
    if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
            and dec.func.attr in HTTP_METHODS and dec.args
            and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str)):
        return None
    deps: list[str | None] = []
    for keyword in dec.keywords:
        if keyword.arg == "dependencies" and isinstance(keyword.value, (ast.List, ast.Tuple)):
            deps += [_depends_target(e) for e in keyword.value.elts]
    deps += [_depends_target(d) for d in _param_defaults(fn)]
    args = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    params = [f"{a.arg}: {ast.unparse(a.annotation)}" if a.annotation else a.arg for a in args]
    return Route(dec.func.attr.upper(), dec.args[0].value, fn.name, rel, fn.lineno,
                 [d for d in deps if d], params)


def list_routes(fs: RepoFS, glob: str = "*router*.py") -> list[Route]:
    routes = []
    for rel in _python_files(fs, glob):
        tree = _parse(fs, rel)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, _FUNCS):
                routes += [r for d in node.decorator_list if (r := _route(node, d, rel))]
    return sorted(routes, key=lambda r: (r.file, r.line))


def format_routes(routes: list[Route]) -> str:
    if not routes:
        return "(không tìm thấy route nào)"
    lines = [f"{r.method} {r.path} → {r.function} ({r.file}:{r.line}) "
             f"| Depends: {', '.join(r.dependencies) or '-'} | params: {', '.join(r.params)}"
             for r in routes]
    return wrap_untrusted("routes", "\n".join(lines))


def get_function(fs: RepoFS, file: str, name: str) -> str:
    tree = _parse(fs, fs.relative(file))
    if tree is None:
        return f"ERROR: không phân tích được {file}"
    target: ast.AST | None = None
    scope: list[ast.stmt] = tree.body
    parts = name.split(".")
    for index, part in enumerate(parts):
        found = next((n for n in scope if isinstance(n, (*_FUNCS, ast.ClassDef))
                      and n.name == part), None)
        if found is None:
            break
        if index == len(parts) - 1:
            target = found
        scope = found.body
    if target is None:
        target = next((n for n in ast.walk(tree) if isinstance(n, _FUNCS)
                       and n.name == parts[-1]), None)
    if target is None:
        return f"ERROR: không có hàm {name} trong {file}"
    start = min([target.lineno] + [d.lineno for d in getattr(target, "decorator_list", [])])
    return fs.read_file(file, start, target.end_lineno)


def find_callers(fs: RepoFS, name: str, glob: str = "*.py", limit: int = 50) -> str:
    hits: set[tuple[str, int, str]] = set()
    for rel in _python_files(fs, glob):
        tree = _parse(fs, rel)
        if tree is None:
            continue
        lines = fs.lines(rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                called = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
                if called == name:
                    hits.add((rel, node.lineno, lines[node.lineno - 1].strip()[:200]))
    if not hits:
        return "(không tìm thấy lời gọi nào)"
    ordered = sorted(hits)[:limit]
    return wrap_untrusted(f"callers of {name}",
                          redact("\n".join(f"{f}:{n}: {code}" for f, n, code in ordered)))
