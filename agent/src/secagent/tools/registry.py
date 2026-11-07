"""Tool registry: provider-portable JSON schemas, argument validation, safe error reporting."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel, Field, ValidationError

from secagent.context.diff import PrDiff
from secagent.context.redact import redact
from secagent.context.sarif import Cluster
from secagent.tools.deps import get_dependency_usage
from secagent.tools.fs import AccessDenied, RepoFS, ToolError, wrap_untrusted
from secagent.tools.pyast import find_callers, format_routes, get_function, list_routes
from secagent.tools.search import search_code

MAX_OUTPUT = 12_000
TRUNCATED = "\n[…truncated]"


@dataclass
class ToolSpec:
    name: str
    description: str
    args_model: type[BaseModel]
    handler: Callable[[BaseModel], str]


def portable_schema(model: type[BaseModel]) -> dict:
    """JSON schema every provider accepts: no $ref/$defs, Optional[X] as X, no titles."""
    raw = model.model_json_schema()
    defs = raw.pop("$defs", {})

    def walk(node):
        if isinstance(node, list):
            return [walk(item) for item in node]
        if not isinstance(node, dict):
            return node
        if "$ref" in node:
            target = defs[node["$ref"].rsplit("/", 1)[-1]]
            return walk({**target, **{k: v for k, v in node.items() if k != "$ref"}})
        out = {}
        for key, value in node.items():
            if key == "title":
                continue
            if key == "properties":
                out[key] = {name: walk(sub) for name, sub in value.items()}
            else:
                out[key] = walk(value)
        options = out.pop("anyOf", None)
        if options is not None:
            non_null = [o for o in options if o.get("type") != "null"]
            out = {**non_null[0], **out} if len(non_null) == 1 else {**out, "anyOf": non_null}
        if "default" in out and out["default"] is None:
            del out["default"]
        return out

    return walk(raw)


class ToolRegistry:
    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}

    def add(self, spec: ToolSpec) -> None:
        self._specs[spec.name] = spec

    def names(self) -> list[str]:
        return list(self._specs)

    def schemas(self) -> list[dict]:
        return [{"type": "function",
                 "function": {"name": s.name, "description": s.description,
                              "parameters": portable_schema(s.args_model)}}
                for s in self._specs.values()]

    def call(self, name: str, raw_args: str) -> str:
        spec = self._specs.get(name)
        if spec is None:
            return f"ERROR: unknown tool {name[:100]}"
        try:
            data = json.loads(raw_args or "{}")
            if not isinstance(data, dict):
                raise ValueError("arguments must be a JSON object")
            args = spec.args_model.model_validate(data)
        except (ValueError, ValidationError) as exc:
            return f"ERROR: invalid arguments: {str(exc)[:500]}"
        try:
            out = spec.handler(args)
        except AccessDenied as exc:
            return f"ERROR: access denied: {exc}"
        except ToolError as exc:
            return f"ERROR: {exc}"
        except Exception as exc:  # a tool bug must not end the review session
            return f"ERROR: {type(exc).__name__}"
        return out if len(out) <= MAX_OUTPUT else out[:MAX_OUTPUT] + TRUNCATED


# --- read-only tools ---------------------------------------------------------------------


class GetDiffArgs(BaseModel):
    path: str | None = Field(default=None, description="One changed file; omit for the whole diff")


class ReadFileArgs(BaseModel):
    path: str = Field(description="Path relative to the repository root")
    start_line: int = Field(default=1, ge=1)
    end_line: int | None = Field(default=None, ge=1, description="At most 400 lines per call")


class SearchArgs(BaseModel):
    pattern: str = Field(description="Python regular expression, at most 200 characters")
    glob: str = Field(default="*.py", description="fnmatch pattern on repo-relative paths")


class ListFilesArgs(BaseModel):
    glob: str = Field(default="*", description="fnmatch pattern, e.g. app/medicare/*router*.py")


class NoArgs(BaseModel):
    pass


class ClusterArgs(BaseModel):
    cluster_id: str = Field(description="Finding cluster id, e.g. F1")


class RoutesArgs(BaseModel):
    glob: str = Field(default="*router*.py")


class FunctionArgs(BaseModel):
    file: str
    name: str = Field(description="Function name, or Class.method")


class CallersArgs(BaseModel):
    name: str = Field(description="Function or method name")
    glob: str = Field(default="*.py")


class DependencyArgs(BaseModel):
    package: str = Field(description="PyPI package name, e.g. pyyaml")


class RequirementsArgs(BaseModel):
    rule_id: str | None = Field(default=None, pattern=r"^R-\d{2}$",
                                description="One rule such as R-01; omit for all rules")


def _cluster_line(c: Cluster) -> str:
    where = f"{c.file}:{c.line}" if c.file else "(không có vị trí)"
    rules = ", ".join(sorted({f"{f.tool}:{f.rule_id}" for f in c.findings}))
    return (f"{c.id} | {c.severity} | {', '.join(c.tools)} | {', '.join(c.cwes) or '-'} | "
            f"{where} | {'trong diff' if c.in_diff else 'có từ trước'} | {rules} | "
            f"{c.findings[0].message[:160]}")


def format_findings(clusters: list[Cluster]) -> str:
    if not clusters:
        return "(công cụ quét không có phát hiện nào cần thẩm định)"
    header = "id | mức | công cụ | CWE | vị trí | trong diff? | rule | message"
    return "\n".join([header, *(_cluster_line(c) for c in clusters)])


def _finding_detail(fs: RepoFS, cluster: Cluster) -> str:
    parts = [_cluster_line(cluster), "finding_ids:"]
    for f in cluster.findings:
        parts.append(f"- {f.id} | {f.severity} | {', '.join(f.cwes) or '-'} | {f.message}")
        if f.related:
            parts.append(f"  liên quan: {', '.join(f.related)}")
    if cluster.file:
        try:
            parts.append(fs.read_file(cluster.file, max(1, cluster.line - 5),
                                      max(cluster.end_line, cluster.line) + 5))
        except ToolError as exc:
            parts.append(f"(không đọc được code: {exc})")
    return "\n".join(parts)


def _requirement(text: str, rule_id: str | None) -> str:
    if rule_id is None:
        return wrap_untrusted("docs/security-requirements.md", text)
    match = re.search(rf"^###\s+{re.escape(rule_id)}\b.*?(?=^###\s|\Z)", text, re.S | re.M)
    if match is None:
        raise ToolError(f"không có quy tắc {rule_id}")
    return wrap_untrusted(f"docs/security-requirements.md#{rule_id}", match.group(0).strip())


def build_read_tools(fs: RepoFS, diff: PrDiff, clusters: list[Cluster], requirements: str | None,
                     use_ast: bool) -> list[ToolSpec]:
    by_id = {c.id: c for c in clusters}

    def get_diff(a: GetDiffArgs) -> str:
        if a.path is None:
            return wrap_untrusted("PR diff", diff.text())
        fd = diff.files.get(a.path.replace("\\", "/"))
        if fd is None:
            raise ToolError(f"{a.path} không nằm trong diff của PR")
        return wrap_untrusted(f"diff {fd.path}", redact(fd.patch))

    def get_finding(a: ClusterArgs) -> str:
        cluster = by_id.get(a.cluster_id)
        if cluster is None:
            raise ToolError(f"không có cụm {a.cluster_id}; dùng list_findings")
        return _finding_detail(fs, cluster)

    specs = [
        ToolSpec("get_diff", "Unified diff of the Pull Request (whole, or one file).",
                 GetDiffArgs, get_diff),
        ToolSpec("read_file", "Read lines of a repository file, with line numbers.",
                 ReadFileArgs, lambda a: fs.read_file(a.path, a.start_line, a.end_line)),
        ToolSpec("search_code", "Regex search in repository files; returns path:line: code.",
                 SearchArgs, lambda a: search_code(fs, a.pattern, a.glob)),
        ToolSpec("list_files", "List repository files matching a glob.",
                 ListFilesArgs, lambda a: fs.list_files(a.glob)),
        ToolSpec("list_findings", "Scanner finding clusters to judge in this review.",
                 NoArgs, lambda a: format_findings(clusters)),
        ToolSpec("get_finding", "Details of one cluster: every scanner finding id and the code.",
                 ClusterArgs, get_finding),
    ]
    if use_ast:
        specs += [
            ToolSpec("list_routes", "FastAPI routes: method, path, handler, Depends (authz).",
                     RoutesArgs, lambda a: format_routes(list_routes(fs, a.glob))),
            ToolSpec("get_function", "Source of one function or Class.method, with decorators.",
                     FunctionArgs, lambda a: get_function(fs, a.file, a.name)),
            ToolSpec("find_callers", "Call sites of a function or method name.",
                     CallersArgs, lambda a: find_callers(fs, a.name, a.glob)),
        ]
    specs.append(ToolSpec("get_dependency_usage",
                          "Locked version of a package in app/uv.lock and where it is imported.",
                          DependencyArgs, lambda a: get_dependency_usage(fs, a.package)))
    if requirements is not None:
        specs.append(ToolSpec("read_security_requirements",
                              "MediCare business security rules R-01..R-15 (all, or one).",
                              RequirementsArgs, lambda a: _requirement(requirements, a.rule_id)))
    return specs
