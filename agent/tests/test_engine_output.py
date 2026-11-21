import json
from pathlib import Path

import pytest

from secagent.engine.output import (
    EngineOutputError,
    ExecutionSummary,
    extract_engine_output,
    parse_execution,
)

FIXTURES = Path(__file__).parent / "fixtures" / "engine"


def verdict_doc(confidence=0.9):
    return {"verdicts": [{"cluster_id": "F1", "verdict": "TP", "confidence": confidence,
                          "severity": "HIGH", "reasoning": "SQL noi chuoi."}]}


def summary(result_text=None, structured=None, is_error=False):
    return ExecutionSummary(result_text=result_text, structured=structured, model=None,
                            num_turns=1, tool_calls=0, tokens_in=0, tokens_out=0,
                            cost_usd=0.0, duration_s=0.0, is_error=is_error, tool_events=[])


@pytest.mark.parametrize("name", ["result.json", "messages.json", "stream.jsonl"])
def test_parse_three_formats(name):
    s = parse_execution(FIXTURES / name)
    assert s.model == "claude-sonnet-5-5"
    assert s.num_turns == 5
    assert s.cost_usd == pytest.approx(0.12)
    assert s.duration_s == pytest.approx(12.345)
    assert not s.is_error
    assert extract_engine_output(s).verdicts[0].cluster_id == "F1"


def test_counts_tools_and_tokens():
    s = parse_execution(FIXTURES / "messages.json")
    assert s.tool_calls == 2
    assert [e["name"] for e in s.tool_events] == ["Read", "Grep"]
    assert "app/routes.py" in s.tool_events[0]["input"]
    assert s.tokens_in == 100 + 1000 + 200
    assert s.tokens_out == 50


def test_missing_usage_keys_count_as_zero(tmp_path):
    f = tmp_path / "r.json"
    f.write_text(json.dumps({"type": "result", "result": "x", "usage": {"output_tokens": 7}}),
                 encoding="utf-8")
    s = parse_execution(f)
    assert (s.tokens_in, s.tokens_out, s.cost_usd, s.num_turns) == (0, 7, 0.0, 0)


def test_tool_input_is_truncated(tmp_path):
    msgs = [{"type": "assistant", "message": {"content": [
                {"type": "tool_use", "name": "Grep", "input": {"pattern": "x" * 1000}}]}},
            {"type": "result", "result": "x"}]
    f = tmp_path / "m.json"
    f.write_text(json.dumps(msgs), encoding="utf-8")
    s = parse_execution(f)
    assert len(s.tool_events[0]["input"]) == 300


def test_last_json_block_wins():
    text = ("Nhap dau:\n```json\n{\"verdicts\": [{\"cluster_id\": \"BAD\"}]}\n```\n"
            "Ket luan:\n```json\n" + json.dumps(verdict_doc()) + "\n```\n")
    assert extract_engine_output(summary(result_text=text)).verdicts[0].cluster_id == "F1"


def test_structured_output_preferred():
    s = summary(result_text="khong co json", structured=verdict_doc())
    assert extract_engine_output(s).verdicts[0].cluster_id == "F1"


def test_balanced_object_fallback():
    text = "Day la ket qua " + json.dumps(verdict_doc()) + " het."
    assert extract_engine_output(summary(result_text=text)).verdicts[0].cluster_id == "F1"


def test_error_and_garbage_raise(tmp_path):
    with pytest.raises(EngineOutputError):
        extract_engine_output(parse_execution(FIXTURES / "error.json"))
    with pytest.raises(EngineOutputError):
        parse_execution(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    with pytest.raises(EngineOutputError):
        parse_execution(bad)
    no_result = tmp_path / "no_result.json"
    no_result.write_text(json.dumps([{"type": "system", "subtype": "init"}]), encoding="utf-8")
    with pytest.raises(EngineOutputError):
        parse_execution(no_result)
    with pytest.raises(EngineOutputError):
        extract_engine_output(summary(result_text="Chi co van ban, khong co JSON."))
    with pytest.raises(EngineOutputError):
        extract_engine_output(summary(result_text=None))


def test_schema_violation_raises():
    text = "```json\n" + json.dumps(verdict_doc(confidence=1.5)) + "\n```"
    with pytest.raises(EngineOutputError):
        extract_engine_output(summary(result_text=text))
