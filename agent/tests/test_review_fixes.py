"""Regression tests for the plan C final review findings (I3 to I7)."""

import json
import os

import httpx2 as httpx
import pytest
from fakes import (
    ScriptedLLM,
    call,
    commit_all,
    git,
    miniapp_repo,
    reply,
    write_files,
)
from pydantic import BaseModel
from test_cli import argv, run_main, sarif, scenario, scripted
from test_sarif import _gate

from secagent.config import Settings
from secagent.context.sarif import ScanFinding, filter_changed
from secagent.llm.anthropic_client import AnthropicClient
from secagent.llm.base import LLMError, ToolCall
from secagent.llm.openai_compat import OpenAIChatClient
from secagent.models import Report
from secagent.tools.registry import ToolRegistry, ToolSpec

# --- I5: same finding set as the gate, most severe first ----------------------------------


def test_filter_changed_matches_the_gate():
    rows = [("semgrep", "a", "app/a.py", 3, ()), ("semgrep", "b", "app/old.py", 3, ()),
            ("codeql", "c", "app/common/db.py", 9, ("app/a.py",)),
            ("checkov", "d", "infra/terraform/main.tf", 5, ()),
            ("checkov", "e", "infra/k8s/x.yaml", 1, ()),
            ("gitleaks", "f", "app/renamed.py", 1, ()), ("trivy", "g", "", 0, ())]
    changed = {"app/a.py", "infra/terraform/variables.tf"}
    ours = [ScanFinding(t, r, "HIGH", f, n, n, "m", (), rel) for t, r, f, n, rel in rows]
    theirs = [_gate().Finding(t, r, "HIGH", f, n, rel) for t, r, f, n, rel in rows]
    kept = [x.id for x in filter_changed(ours, changed)]
    assert kept == [x.id for x in _gate().filter_changed(theirs, changed)] and len(kept) == 5


def test_agent_only_judges_findings_in_changed_files(tmp_path):
    repo, base, head, sarif_dir, line = scenario(tmp_path)
    (sarif_dir / "checkov.sarif").write_text(json.dumps(
        sarif("checkov", "CKV_AWS_1", "infra/terraform/main.tf", 5, cwe="CWE-284")))
    out = tmp_path / "out"
    assert run_main(argv(repo, base, head, sarif_dir, out), scripted(line)) == 0
    report = Report.model_validate_json((out / "report.json").read_text(encoding="utf-8"))
    assert [e.source for e in report.findings] == ["semgrep"]


# --- I3 / I4: secrets and path confinement ------------------------------------------------


def _leak_repo(tmp_path, secret):
    repo = miniapp_repo(tmp_path)
    base = git(repo, "rev-parse", "HEAD")
    write_files(repo, {"app/settings.cfg": f"MAIL_PASS={secret}\nMAIL_HOST=smtp\n"})
    head = commit_all(repo, "cfg")
    sarif_dir = tmp_path / "sarif"
    sarif_dir.mkdir()
    (sarif_dir / "gitleaks.sarif").write_text(json.dumps(
        sarif("gitleaks", "generic-api-key", "app/settings.cfg", 1, cwe="CWE-798")))
    return repo, base, head, sarif_dir


def test_gitleaks_lines_never_reach_the_llm(tmp_path):
    secret = "Mail" + "Pass" + "77xyz"  # unquoted: the regex redaction cannot see it
    repo, base, head, sarif_dir = _leak_repo(tmp_path, secret)
    llm = ScriptedLLM([
        reply(call("get_diff"), call("get_diff", path="app/settings.cfg"),
              call("read_file", path="app/settings.cfg"),
              call("search_code", pattern="MAIL", glob="*.cfg")),
        reply(call("submit_verdict", cluster_id="F1", verdict="TP", confidence=1, severity="HIGH",
                   reasoning="lộ mật khẩu",
                   evidence=[{"file": "app/settings.cfg", "start_line": 1, "end_line": 1}]),
              call("finish")),
    ])
    out = tmp_path / "out"
    assert run_main(argv(repo, base, head, sarif_dir, out), llm) == 0
    assert secret not in json.dumps([c["messages"] for c in llm.calls], ensure_ascii=False)
    for name in ("trace.jsonl", "report.json", "report.md"):
        assert secret not in (out / name).read_text(encoding="utf-8"), name


def test_requirements_are_read_inside_the_repo_and_redacted(tmp_path):
    key = "AKIA" + "R" * 16
    repo, base, head, sarif_dir, line = scenario(tmp_path)
    req = repo / "docs" / "security-requirements.md"
    req.write_text(req.read_text(encoding="utf-8") + f'\napi_key: "{key}"\n', encoding="utf-8")
    llm = scripted(line)
    assert run_main(argv(repo, base, head, sarif_dir, tmp_path / "out"), llm) == 0
    prompt = llm.calls[0]["messages"][1]["content"]
    assert "Bệnh nhân chỉ xem được hồ sơ" in prompt and key not in prompt


def test_requirements_symlink_out_of_the_repo_is_ignored(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("TOP-SECRET-OUTSIDE", encoding="utf-8")
    repo, base, head, sarif_dir, line = scenario(tmp_path / "s")
    req = repo / "docs" / "security-requirements.md"
    req.unlink()
    try:
        os.symlink(outside, req)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not permitted on this machine")
    llm = scripted(line)
    assert run_main(argv(repo, base, head, sarif_dir, tmp_path / "out"), llm) == 0
    assert "TOP-SECRET-OUTSIDE" not in json.dumps(llm.calls, ensure_ascii=False)


class _NoArgs(BaseModel):
    pass


def test_registry_tolerates_missing_names_and_redacts_outputs():
    key = "sk-" + "e5f6" * 8
    reg = ToolRegistry()
    reg.add(ToolSpec("t", "d", _NoArgs, lambda a: f"value {key}"))
    assert reg.call(None, None).startswith("ERROR: unknown tool")
    assert key not in reg.call("t", "{}")


# --- I7: malformed provider output -------------------------------------------------------


def _settings(provider="gemini") -> Settings:
    return Settings.from_env({"LLM_API_KEY": "k", "LLM_PROVIDER": provider}, mode="ci")


def _transport(response: httpx.Response) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(lambda request: response))


@pytest.mark.parametrize("client_class,provider", [(OpenAIChatClient, "gemini"),
                                                   (AnthropicClient, "anthropic")])
def test_malformed_response_becomes_llm_error(client_class, provider):
    html = httpx.Response(200, text="<html>oops</html>", headers={"content-type": "text/html"})
    client = client_class(_settings(provider), http_client=_transport(html), sleep=lambda _: None)
    with pytest.raises(LLMError):
        client.complete([{"role": "user", "content": "x"}], [])


def test_openai_tool_call_without_name_is_tolerated():
    body = {"id": "c", "object": "chat.completion", "created": 1, "model": "m",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None,
                "tool_calls": [{"id": "c1", "type": "function",
                                "function": {"name": None, "arguments": None}}]}}]}
    client = OpenAIChatClient(_settings(), http_client=_transport(httpx.Response(200, json=body)),
                              sleep=lambda _: None)
    assert client.complete([{"role": "user", "content": "x"}], []).tool_calls == [
        ToolCall("c1", "", "{}")]


