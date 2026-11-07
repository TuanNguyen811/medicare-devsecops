import json

import pytest
from fakes import miniapp_repo
from pydantic import BaseModel

from secagent.context.diff import parse_unified_diff
from secagent.context.sarif import ScanFinding, cluster_findings
from secagent.models import NewFindingArgs, VerdictArgs
from secagent.tools.fs import AccessDenied, RepoFS, ToolError
from secagent.tools.registry import ToolRegistry, ToolSpec, build_read_tools, portable_schema

ALL_READ_TOOLS = {"get_diff", "read_file", "search_code", "list_files", "list_findings",
                  "get_finding", "list_routes", "get_function", "find_callers",
                  "get_dependency_usage", "read_security_requirements"}
DIFF = parse_unified_diff(
    "diff --git a/app/medicare/demo/service.py b/app/medicare/demo/service.py\n"
    "--- a/app/medicare/demo/service.py\n+++ b/app/medicare/demo/service.py\n"
    "@@ -1,2 +1,3 @@\n def load_item(item_id: int) -> dict:\n+    audit(item_id)\n"
    "     return {\"id\": item_id}\n")
REQUIREMENTS = "# R\n\n### R-01: Một\nNội dung một.\n\n### R-03: Ba\nNội dung ba.\n"


class Args(BaseModel):
    path: str = "a"
    n: int = 1


def _handler(args: Args) -> str:
    if args.path == "deny":
        raise AccessDenied("app/.env")
    if args.path == "tool":
        raise ToolError("file quá lớn")
    if args.path == "boom":
        raise RuntimeError("internal detail")
    return "y" * 20_000 if args.path == "big" else f"ok {args.path} {args.n}"


def test_registry_errors():
    reg = ToolRegistry()
    reg.add(ToolSpec("t", "test tool", Args, _handler))
    assert reg.call("t", '{"path": "b", "n": 2}') == "ok b 2"
    assert reg.call("t", "") == "ok a 1"
    assert reg.call("rm_rf", "{}").startswith("ERROR: unknown tool rm_rf")
    assert reg.call("t", "{not json").startswith("ERROR: invalid arguments")
    assert reg.call("t", "[1, 2]").startswith("ERROR: invalid arguments")
    assert reg.call("t", '{"n": "x"}').startswith("ERROR: invalid arguments")
    assert reg.call("t", '{"path": "deny"}') == "ERROR: access denied: app/.env"
    assert reg.call("t", '{"path": "tool"}') == "ERROR: file quá lớn"
    assert reg.call("t", '{"path": "boom"}') == "ERROR: RuntimeError"
    big = reg.call("t", '{"path": "big"}')
    assert len(big) <= 12_000 + 20 and big.endswith("[…truncated]")
    (schema,) = reg.schemas()
    assert schema["type"] == "function" and schema["function"]["name"] == "t"
    assert schema["function"]["parameters"]["properties"]["n"]["type"] == "integer"
    assert reg.names() == ["t"]


def _clusters():
    f = ScanFinding("semgrep", "medicare.sqlalchemy-text-fstring", "HIGH",
                    "app/medicare/demo/service.py", 2, 2, "SQL ghép chuỗi", ("CWE-89",), ())
    return cluster_findings([f], DIFF)


def _tools(tmp_path, requirements=REQUIREMENTS, use_ast=True):
    reg = ToolRegistry()
    for spec in build_read_tools(RepoFS(miniapp_repo(tmp_path)), DIFF, _clusters(), requirements,
                                 use_ast):
        reg.add(spec)
    return reg


def test_read_tools_work_end_to_end(tmp_path):
    reg = _tools(tmp_path)
    assert set(reg.names()) == ALL_READ_TOOLS
    assert "+    audit(item_id)" in reg.call("get_diff", "{}")
    assert "audit" in reg.call("get_diff", '{"path": "app/medicare/demo/service.py"}')
    assert reg.call("get_diff", '{"path": "nope.py"}').startswith("ERROR")
    assert "F1" in reg.call("list_findings", "{}") and "CWE-89" in reg.call("list_findings", "{}")
    detail = reg.call("get_finding", '{"cluster_id": "F1"}')
    assert "semgrep:medicare.sqlalchemy-text-fstring:app/medicare/demo/service.py:2" in detail
    assert "    1| def load_item" in detail
    assert reg.call("get_finding", '{"cluster_id": "F9"}').startswith("ERROR")
    assert "Nội dung ba." in reg.call("read_security_requirements", '{"rule_id": "R-03"}')
    assert "Nội dung một." not in reg.call("read_security_requirements", '{"rule_id": "R-03"}')
    assert reg.call("read_security_requirements", '{"rule_id": "R-09"}').startswith("ERROR")
    assert "GET /items/{item_id}" in reg.call("list_routes", "{}")
    assert "pyyaml 5.3.1" in reg.call("get_dependency_usage", '{"package": "pyyaml"}')
    assert reg.call("read_file", '{"path": "../etc/passwd"}').startswith("ERROR: access denied")


def test_ablation_toolsets(tmp_path):
    names = set(_tools(tmp_path, requirements=None, use_ast=False).names())
    assert names == ALL_READ_TOOLS - {"list_routes", "get_function", "find_callers",
                                      "read_security_requirements"}


def _assert_portable(node):
    if isinstance(node, dict):
        assert not {"$ref", "$defs", "anyOf", "title"} & set(node), node
        for key, value in node.items():
            if key == "properties":
                for sub in value.values():
                    _assert_portable(sub)
            else:
                _assert_portable(value)
    elif isinstance(node, list):
        for item in node:
            _assert_portable(item)


@pytest.mark.parametrize("model", [VerdictArgs, NewFindingArgs])
def test_tool_schemas_are_portable(model, tmp_path):
    schema = portable_schema(model)
    _assert_portable(schema)
    assert schema["type"] == "object"
    assert json.dumps(schema).count("$ref") == 0


def test_portable_schema_keeps_constraints(tmp_path):
    v = portable_schema(VerdictArgs)
    assert set(v["required"]) == {"cluster_id", "verdict", "confidence", "severity", "reasoning"}
    assert v["properties"]["cwe"] == {"type": "string", "pattern": "^CWE-\\d+$"}
    assert v["properties"]["verdict"]["enum"] == ["TP", "FP", "NEEDS_REVIEW"]
    assert v["properties"]["confidence"]["minimum"] == 0
    evidence = v["properties"]["evidence"]["items"]
    assert evidence["properties"]["start_line"]["minimum"] == 1 and "file" in evidence["required"]
    assert v["properties"]["fix"]["type"] == "object"
    assert portable_schema(NewFindingArgs)["properties"]["evidence"]["minItems"] == 1
    for spec in build_read_tools(RepoFS(miniapp_repo(tmp_path)), DIFF, _clusters(), REQUIREMENTS,
                                 True):
        _assert_portable(portable_schema(spec.args_model))
