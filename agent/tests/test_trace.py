import json

from secagent.trace import Trace


def test_trace_redacts_and_writes_jsonl(tmp_path):
    key = "AKIA" + "Q" * 16
    trace = Trace(tmp_path / "trace.jsonl")
    trace.event("tool", name="read_file", result=f'KEY = "{key}"',
                nested={"messages": [f"x {key}", 3]}, long="a" * 5000)
    trace.event("llm", step=1)
    trace.close()
    lines = (tmp_path / "trace.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and key not in lines[0]
    record = json.loads(lines[0])
    assert record["kind"] == "tool" and record["t"].endswith("+00:00")
    assert record["nested"]["messages"][1] == 3 and len(record["long"]) <= 4001
    assert json.loads(lines[1])["step"] == 1


def test_trace_without_path_is_a_no_op(tmp_path):
    trace = Trace(None)
    trace.event("x", a=1)
    trace.close()
    assert list(tmp_path.iterdir()) == []
