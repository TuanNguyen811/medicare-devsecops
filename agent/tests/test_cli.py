import json
import subprocess
import sys

from fakes import REPO_ROOT, ScriptedLLM, call, commit_all, git, miniapp_repo, reply, write_files

from secagent.cli import main
from secagent.llm.base import LLMError
from secagent.models import Report
from secagent.report.markdown import MARKER

SERVICE = "app/medicare/demo/service.py"
VULN = "    return db.execute(text(f\"SELECT * FROM items WHERE name = '{q}'\"))"
FIXED = '    return db.execute(text("SELECT * FROM items WHERE name = :q"), {"q": q})'
GATE = REPO_ROOT / "security" / "gate" / "gate.py"


def sarif(tool, rule, file, line, score=None, cwe="CWE-89", message="finding") -> dict:
    props = {"tags": [f"{cwe}: weakness"]}
    if score:
        props["security-severity"] = score
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": tool, "rules": [{"id": rule, "properties": props}]}},
        "results": [{"ruleId": rule, "level": "error", "message": {"text": message},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": file},
                                                         "region": {"startLine": line}}}]}]}]}


def scenario(tmp_path, score=None):
    repo = miniapp_repo(tmp_path)
    base = git(repo, "rev-parse", "HEAD")
    text = (repo / SERVICE).read_text(encoding="utf-8") + f"\n\ndef search(db, q: str):\n{VULN}\n"
    write_files(repo, {SERVICE: text})
    head = commit_all(repo, "tìm kiếm")
    line = text.splitlines().index(VULN) + 1
    sarif_dir = tmp_path / "sarif"
    sarif_dir.mkdir()
    (sarif_dir / "semgrep.sarif").write_text(json.dumps(
        sarif("semgrep", "medicare.sqlalchemy-text-fstring", SERVICE, line)))
    (sarif_dir / "codeql.sarif").write_text(json.dumps(
        sarif("codeql", "py/sql-injection", SERVICE, line, score=score)))
    return repo, base, head, sarif_dir, line


def argv(repo, base, head, sarif_dir, out, mode="ci"):
    return ["--mode", mode, "--repo", str(repo), "--base", base, "--head", head,
            "--sarif-dir", str(sarif_dir), "--requirements", "docs/security-requirements.md",
            "--out", str(out)]


def fix_patch(line: int) -> str:
    return (f"--- a/{SERVICE}\n+++ b/{SERVICE}\n@@ -{line},1 +{line},1 @@\n"
            f"-{VULN}\n+{FIXED}\n")


def verdict(line: int, v="TP", snippet="return db.execute(") -> dict:
    return {"cluster_id": "F1", "verdict": v, "confidence": 0.95, "severity": "HIGH",
            "cwe": "CWE-89", "owasp": "A05", "reasoning": "q ghép thẳng vào câu SQL",
            "evidence": [{"file": SERVICE, "start_line": line, "end_line": line,
                          "snippet": snippet}],
            "exploit_scenario": "q = ' OR 1=1 --",
            "fix": {"description": "Dùng bind parameter", "patch": fix_patch(line)}}


def scripted(line: int, v="TP") -> ScriptedLLM:
    return ScriptedLLM([
        reply(call("read_file", path=SERVICE, start_line=line - 1, end_line=line)),
        reply(call("submit_verdict", **verdict(line, v)), call("finish", summary="xong")),
    ])


def run_main(args, llm=None, env=None):
    return main(args, llm_factory=(lambda s: llm) if llm else None,
                env={"LLM_API_KEY": "k-test"} if env is None else env)


def gate(sarif_dir, out, *extra):
    return subprocess.run([sys.executable, str(GATE), "--sarif-dir", str(sarif_dir), "--mode",
                           "ai-assisted", "--report", str(out / "report.json"),
                           "--agent-exit", "0", *extra],
                          capture_output=True, text=True, encoding="utf-8", check=False)


def test_cli_end_to_end_writes_contract_outputs(tmp_path):
    repo, base, head, sarif_dir, line = scenario(tmp_path)
    out = tmp_path / "out"
    assert run_main(argv(repo, base, head, sarif_dir, out), scripted(line)) == 0
    for name in ("report.json", "report.md", "agent.sarif", "trace.jsonl", "review.json"):
        assert (out / name).is_file(), name
    report = Report.model_validate_json((out / "report.json").read_text(encoding="utf-8"))
    (entry,) = report.findings
    assert entry.finding_ids == sorted([
        f"codeql:py/sql-injection:{SERVICE}:{line}",
        f"semgrep:medicare.sqlalchemy-text-fstring:{SERVICE}:{line}"])
    assert entry.verdict == "TP" and entry.fix.patch == fix_patch(line)
    assert (report.meta.llm_calls, report.meta.model, report.meta.tokens_in) == (
        2, "deepseek-chat", 200)
    review = json.loads((out / "review.json").read_text(encoding="utf-8"))
    assert review["comments"][0]["line"] == line and FIXED in review["comments"][0]["body"]


def test_report_drives_the_gate(tmp_path):
    repo, base, head, sarif_dir, line = scenario(tmp_path)
    out = tmp_path / "out"
    run_main(argv(repo, base, head, sarif_dir, out), scripted(line, "TP"))
    assert gate(sarif_dir, out).returncode == 1
    out_fp = tmp_path / "out-fp"
    run_main(argv(repo, base, head, sarif_dir, out_fp), scripted(line, "FP"))
    assert gate(sarif_dir, out_fp).returncode == 0, gate(sarif_dir, out_fp).stdout
    repo2, base2, head2, sarif2, line2 = scenario(tmp_path / "crit", score="9.8")
    out_crit = tmp_path / "out-crit"
    run_main(argv(repo2, base2, head2, sarif2, out_crit), scripted(line2, "FP"))
    assert gate(sarif2, out_crit).returncode == 1
    assert gate(sarif2, out_crit, "--labels", "security-reviewed").returncode == 0


def test_cli_exit_codes(tmp_path):
    repo, base, head, sarif_dir, _ = scenario(tmp_path)
    out = tmp_path / "no-key"
    assert run_main(argv(repo, base, head, sarif_dir, out), env={}) == 2
    assert not out.exists()
    out = tmp_path / "dead"
    assert run_main(argv(repo, base, head, sarif_dir, out),
                    ScriptedLLM([LLMError("APIConnectionError")])) == 2
    text = (out / "report.md").read_text(encoding="utf-8")
    assert text.startswith(MARKER) and "traditional" in text
    assert not (out / "report.json").exists()
    out = tmp_path / "partial"
    llm = ScriptedLLM([reply(call("read_file", path=SERVICE)), LLMError("RateLimitError")])
    assert run_main(argv(repo, base, head, sarif_dir, out), llm) == 0
    report = Report.model_validate_json((out / "report.json").read_text(encoding="utf-8"))
    assert [e.verdict for e in report.findings] == ["NEEDS_REVIEW"]
    assert report.meta.error == "RateLimitError"


def test_trace_and_report_never_contain_secret(tmp_path):
    key = "AKIA" + "Q" * 16
    repo = miniapp_repo(tmp_path)
    base = git(repo, "rev-parse", "HEAD")
    write_files(repo, {"app/sms.py": f'API = "{key}"\nsend = None\n'})
    head = commit_all(repo, "sms")
    sarif_dir = tmp_path / "sarif"
    sarif_dir.mkdir()
    (sarif_dir / "gitleaks.sarif").write_text(json.dumps(
        sarif("gitleaks", "aws-access-token", "app/sms.py", 1, cwe="CWE-798",
              message=f"aws-access-token has detected secret {key}")))
    llm = ScriptedLLM([
        reply(call("read_file", path="app/sms.py"), call("get_finding", cluster_id="F1"),
              call("get_diff")),
        reply(call("submit_verdict", cluster_id="F1", verdict="TP", confidence=1,
                   severity="HIGH", reasoning=f"Lộ khóa {key}",
                   evidence=[{"file": "app/sms.py", "start_line": 1, "end_line": 1}]),
              call("finish")),
    ])
    out = tmp_path / "out"
    assert run_main(argv(repo, base, head, sarif_dir, out), llm) == 0
    for name in ("trace.jsonl", "report.json", "report.md", "agent.sarif"):
        assert key not in (out / name).read_text(encoding="utf-8"), name
    sent = json.dumps([c["messages"] for c in llm.calls], ensure_ascii=False)
    assert key not in sent and "Gitleaks" in sent


def test_cli_mode_streams_steps(tmp_path, capsys):
    repo, base, head, sarif_dir, line = scenario(tmp_path)
    assert run_main(argv(repo, base, head, sarif_dir, tmp_path / "out", mode="cli"),
                    scripted(line)) == 0
    err = capsys.readouterr().err
    assert "[bước 1/" in err and "read_file" in err and "TP" in err
