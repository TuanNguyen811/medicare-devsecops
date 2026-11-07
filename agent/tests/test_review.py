import dataclasses
import itertools

from fakes import MINIAPP, ScriptedLLM, call, miniapp_repo, raw_call, reply

from secagent.config import Settings, step_limit
from secagent.context.diff import parse_unified_diff
from secagent.context.sarif import ScanFinding, cluster_findings
from secagent.llm.base import LLMError
from secagent.phases.review import NUDGE, STEP_EXHAUSTED, ReviewContext, run_review
from secagent.tools.fs import RepoFS
from secagent.trace import Trace

SERVICE = "app/medicare/demo/service.py"
DIFF = parse_unified_diff(
    f"diff --git a/{SERVICE} b/{SERVICE}\n--- a/{SERVICE}\n+++ b/{SERVICE}\n"
    "@@ -1,2 +1,3 @@\n def load_item(item_id: int) -> dict:\n+    audit(item_id)\n"
    '     return {"id": item_id}\n')
REQUIREMENTS = (MINIAPP / "docs" / "security-requirements.md").read_text(encoding="utf-8")
R01_TEXT = "Bệnh nhân chỉ xem được hồ sơ"


def settings(**kw) -> Settings:
    return Settings.from_env({"LLM_API_KEY": "k"}, mode="ci", **kw)


def context(tmp_path, n=1, requirements=True, **kw) -> ReviewContext:
    findings = [ScanFinding("semgrep", f"rule{i}", "HIGH", SERVICE, 1, 1, f"m{i}", (), ())
                for i in range(1, n + 1)]
    return ReviewContext(fs=RepoFS(miniapp_repo(tmp_path)), diff=DIFF,
                         clusters=cluster_findings(findings, DIFF),
                         requirements=REQUIREMENTS if requirements else None,
                         settings=settings(**kw))


def verdict(cluster_id, v="TP", **kw) -> dict:
    data = {"cluster_id": cluster_id, "verdict": v, "confidence": 0.9, "severity": "HIGH",
            "cwe": "CWE-89", "reasoning": "SQL ghép chuỗi",
            "evidence": [{"file": SERVICE, "start_line": 1, "end_line": 1}]}
    data.update(kw)
    return data


def new_finding() -> dict:
    return {"title": "IDOR khi xuất item", "severity": "HIGH", "confidence": 0.8,
            "cwe": "CWE-639", "reasoning": "không kiểm tra quyền sở hữu",
            "evidence": [{"file": "app/medicare/demo/router.py", "start_line": 22,
                          "end_line": 24}]}


def tool_messages(messages):
    return [m for m in messages if m["role"] == "tool"]


def test_agent_reads_then_submits_and_finishes(tmp_path):
    llm = ScriptedLLM([
        reply(call("read_file", path=SERVICE)),
        reply(call("submit_verdict", **verdict("F1")), call("report_finding", **new_finding())),
        reply(call("finish", summary="xong")),
    ])
    out = run_review(context(tmp_path), llm, Trace(None))
    assert out.verdicts["F1"].verdict == "TP" and len(out.new_findings) == 1
    assert (out.llm_calls, out.tool_calls, out.tokens_in, out.tokens_out) == (3, 4, 300, 60)
    assert out.step_limit == 13 and not out.limit_hit and out.error is None
    assert "<untrusted-code" in tool_messages(llm.calls[1]["messages"])[0]["content"]
    assert len(out.sessions) == 1 and out.sessions[0].finished


def test_system_prompt_declares_code_untrusted(tmp_path):
    llm = ScriptedLLM([reply(call("finish"))])
    run_review(context(tmp_path, n=0), llm, Trace(None))
    system, user = llm.calls[0]["messages"][:2]
    assert system["role"] == "system" and "untrusted-code" in system["content"]
    assert R01_TEXT in user["content"] and "+    audit(item_id)" in user["content"]
    assert {"read_security_requirements", "report_finding"} <= set(llm.calls[0]["tool_names"])
    bare = ScriptedLLM([reply(call("finish"))])
    run_review(context(tmp_path / "b", n=0, requirements=False), bare, Trace(None))
    assert R01_TEXT not in bare.calls[0]["messages"][1]["content"]
    assert "read_security_requirements" not in bare.calls[0]["tool_names"]


def test_malformed_tool_calls_are_reported_back(tmp_path):
    llm = ScriptedLLM([
        reply(raw_call("read_file", "{not json"), raw_call("rm_rf", "{}"),
              call("submit_verdict", **verdict("F1", confidence=7))),
        reply(call("submit_verdict", **verdict("F1")), call("finish")),
    ])
    out = run_review(context(tmp_path), llm, Trace(None))
    results = [m["content"] for m in tool_messages(llm.calls[1]["messages"])]
    assert len(results) == 3 and all(r.startswith("ERROR") for r in results)
    assert out.verdicts["F1"].verdict == "TP" and out.error is None


def test_text_only_reply_gets_nudged(tmp_path):
    llm = ScriptedLLM([reply(content="Tôi nghĩ là ổn"), reply(call("finish"))])
    out = run_review(context(tmp_path, n=0), llm, Trace(None))
    assert llm.calls[1]["messages"][-1] == {"role": "user", "content": NUDGE}
    assert out.sessions[0].finished


def test_finish_with_missing_verdicts_warns_once(tmp_path):
    llm = ScriptedLLM([reply(call("submit_verdict", **verdict("F1")), call("finish")),
                       reply(call("finish"))])
    out = run_review(context(tmp_path, n=2), llm, Trace(None))
    warning = tool_messages(llm.calls[1]["messages"])[-1]["content"]
    assert warning.startswith("WARNING") and "F2" in warning
    assert set(out.verdicts) == {"F1"} and out.llm_calls == 2 and not out.limit_hit


def test_step_limit_forces_submission(tmp_path):
    reads = [reply(call("read_file", path=SERVICE)) for _ in range(13)]
    forced = reply(call("read_file", path=SERVICE), call("submit_verdict", **verdict("F1")))
    llm = ScriptedLLM([*reads, forced])
    out = run_review(context(tmp_path), llm, Trace(None))
    assert out.limit_hit and out.llm_calls == 14 and out.verdicts["F1"].verdict == "TP"
    last = llm.calls[13]
    assert last["tool_choice"] == "required"
    assert last["tool_names"] == llm.calls[0]["tool_names"]  # same tools: preserved thinking
    assert "F1" in last["messages"][-1]["content"]
    read_result = tool_messages(out.sessions[0].messages)[-2]["content"]
    assert read_result == STEP_EXHAUSTED


def test_batches_of_15_hunt_only_first(tmp_path):
    llm = ScriptedLLM([
        reply(call("submit_verdict", **verdict("F16"))), reply(call("finish")),
        reply(call("finish")),
        reply(call("finish")), reply(call("finish")),
    ])
    out = run_review(context(tmp_path, n=17), llm, Trace(None))
    assert len(out.sessions) == 2 and out.step_limit == step_limit(15) + step_limit(2)
    assert "report_finding" in llm.calls[0]["tool_names"]
    assert "report_finding" not in llm.calls[3]["tool_names"]
    assert tool_messages(llm.calls[1]["messages"])[0]["content"].startswith(
        "ERROR: unknown cluster_id")
    second_prompt = llm.calls[3]["messages"][1]["content"]
    assert "F16 |" in second_prompt and "F1 |" not in second_prompt
    assert out.verdicts == {}


def test_llm_error_midway_keeps_previous_verdicts(tmp_path):
    llm = ScriptedLLM([reply(call("submit_verdict", **verdict("F1"))),
                       LLMError("RateLimitError (HTTP 429)")])
    out = run_review(context(tmp_path, n=2), llm, Trace(None))
    assert out.verdicts["F1"].verdict == "TP" and "429" in out.error and out.llm_calls == 1


def test_error_leaves_later_batches_unstarted(tmp_path):
    llm = ScriptedLLM([LLMError("APIConnectionError")])
    out = run_review(context(tmp_path, n=17), llm, Trace(None))
    assert out.unstarted == ["F16", "F17"] and len(out.sessions) == 1 and out.llm_calls == 0


def test_token_budget_stops_session(tmp_path):
    ctx = context(tmp_path)
    ctx.settings = dataclasses.replace(ctx.settings, token_budget=150)
    llm = ScriptedLLM([reply(call("read_file", path=SERVICE)) for _ in range(3)])
    out = run_review(ctx, llm, Trace(None))
    assert len(llm.calls) == 2 and out.limit_hit and not out.sessions[0].finished


def test_time_budget_stops_session(tmp_path):
    # started, batch check, turn 1 check → 0 s; every later check → 400 s (> 360 s budget)
    ticks = itertools.chain([0.0, 0.0, 0.0], itertools.repeat(400.0))
    llm = ScriptedLLM([reply(call("read_file", path=SERVICE)) for _ in range(3)])
    out = run_review(context(tmp_path), llm, Trace(None), clock=lambda: next(ticks))
    assert len(llm.calls) == 1 and out.limit_hit


def test_single_shot_one_call_no_read_tools(tmp_path):
    llm = ScriptedLLM([reply(call("submit_verdict", **verdict("F1")), call("finish"))])
    out = run_review(context(tmp_path, strategy="single-shot"), llm, Trace(None))
    assert len(llm.calls) == 1 and out.step_limit == 1
    assert llm.calls[0]["tool_names"] == ["submit_verdict", "report_finding", "finish"]
    assert "    1| def load_item" in llm.calls[0]["messages"][1]["content"]
    assert out.verdicts["F1"].verdict == "TP"


def test_thinking_reasoning_kept_in_history(tmp_path):
    llm = ScriptedLLM([reply(call("read_file", path=SERVICE), reasoning="nghĩ"),
                       reply(call("finish"))])
    run_review(context(tmp_path, n=0), llm, Trace(None))
    assistant = next(m for m in llm.calls[1]["messages"] if m["role"] == "assistant")
    assert assistant["reasoning_content"] == "nghĩ"


def test_events_are_emitted(tmp_path):
    events = []
    llm = ScriptedLLM([reply(call("read_file", path=SERVICE)), reply(call("finish"))])
    run_review(context(tmp_path, n=0), llm, Trace(None), on_event=lambda k, d: events.append(k))
    assert events == ["llm", "tool", "llm", "tool"]
