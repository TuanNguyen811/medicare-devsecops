from fakes import ScriptedLLM, call, miniapp_repo, reply

from secagent.config import Settings
from secagent.context.diff import parse_unified_diff
from secagent.context.sarif import ScanFinding, cluster_findings
from secagent.llm.base import LLMError
from secagent.models import Evidence, NewFindingArgs, VerdictArgs
from secagent.phases.check import build_entries, ensure_coverage, evidence_problems
from secagent.phases.review import ReviewContext, ReviewOutcome, run_review
from secagent.tools.fs import RepoFS
from secagent.trace import Trace

SERVICE = "app/medicare/demo/service.py"
ROUTER = "app/medicare/demo/router.py"
DIFF = parse_unified_diff("")


def settings(**kw) -> Settings:
    return Settings.from_env({"LLM_API_KEY": "k"}, mode="ci", **kw)


def finding(rule, line, tool="semgrep", sev="HIGH", cwes=(), file=SERVICE):
    return ScanFinding(tool, rule, sev, file, line, line, "m", tuple(cwes), ())


def context(tmp_path, findings, **kw) -> ReviewContext:
    return ReviewContext(fs=RepoFS(miniapp_repo(tmp_path)), diff=DIFF,
                         clusters=cluster_findings(findings, DIFF), requirements=None,
                         settings=settings(**kw))


def verdict(cluster_id, v="TP", evidence=None, **kw) -> dict:
    data = {"cluster_id": cluster_id, "verdict": v, "confidence": 0.9, "severity": "HIGH",
            "reasoning": "lý do",
            "evidence": evidence if evidence is not None else [
                {"file": SERVICE, "start_line": 1, "end_line": 1,
                 "snippet": "def load_item(item_id: int) -> dict:"}]}
    data.update(kw)
    return data


def two(tmp_path, **kw) -> ReviewContext:
    return context(tmp_path, [finding("rule1", 1), finding("rule2", 5)], **kw)


def test_coverage_reasks_once_then_needs_review(tmp_path):
    ctx = two(tmp_path)
    llm = ScriptedLLM([reply(call("submit_verdict", **verdict("F1")), call("finish")),
                       reply(call("finish")),
                       reply(call("finish"))])
    out = run_review(ctx, llm, Trace(None))
    assert ensure_coverage(out, ctx.clusters, ctx.settings) == 1
    assert len(llm.calls) == 3 and "F2" in llm.calls[2]["messages"][-1]["content"]
    f2 = next(e for e in build_entries(ctx.clusters, out, ctx.fs)
              if e.finding_ids == ctx.clusters[1].ids)
    assert f2.verdict == "NEEDS_REVIEW" and f2.confidence == 0.0
    assert "không đưa ra kết luận" in f2.reasoning and f2.severity == "HIGH"


def test_coverage_reask_can_fill_the_gap(tmp_path):
    ctx = two(tmp_path)
    fp = verdict("F2", "FP", evidence=[{"file": SERVICE, "start_line": 5, "end_line": 6,
                                        "snippet": "return str(data)"}])
    llm = ScriptedLLM([reply(call("submit_verdict", **verdict("F1")), call("finish")),
                       reply(call("finish")),
                       reply(call("submit_verdict", **fp), call("finish"))])
    out = run_review(ctx, llm, Trace(None))
    assert ensure_coverage(out, ctx.clusters, ctx.settings) == 1
    verdicts = {e.finding_id: e.verdict for e in build_entries(ctx.clusters, out, ctx.fs)}
    assert sorted(verdicts.values()) == ["FP", "TP"]


def test_coverage_skipped_after_limit_or_error(tmp_path):
    ctx = two(tmp_path)
    llm = ScriptedLLM([reply(call("submit_verdict", **verdict("F1"))), LLMError("boom")])
    out = run_review(ctx, llm, Trace(None))
    assert ensure_coverage(out, ctx.clusters, ctx.settings) == 1 and len(llm.calls) == 2
    ctx2 = two(tmp_path / "b")
    llm2 = ScriptedLLM([reply(call("submit_verdict", **verdict("F1")), call("finish")),
                        reply(call("finish"))])
    out2 = run_review(ctx2, llm2, Trace(None))
    out2.limit_hit = True
    assert ensure_coverage(out2, ctx2.clusters, ctx2.settings) == 1 and len(llm2.calls) == 2


def test_single_shot_skips_coverage(tmp_path):
    ctx = two(tmp_path, strategy="single-shot")
    llm = ScriptedLLM([reply(call("submit_verdict", **verdict("F1")), call("finish"))])
    out = run_review(ctx, llm, Trace(None))
    assert ensure_coverage(out, ctx.clusters, ctx.settings) == 1 and len(llm.calls) == 1


def _outcome(verdicts=(), new=()) -> ReviewOutcome:
    out = ReviewOutcome()
    for v in verdicts:
        args = VerdictArgs.model_validate(v)
        out.verdicts[args.cluster_id] = args
    out.new_findings = [NewFindingArgs.model_validate(n) for n in new]
    return out


def test_evidence_problems(tmp_path):
    fs = RepoFS(miniapp_repo(tmp_path))
    ok = [Evidence(file=SERVICE, start_line=1, end_line=1,
                   snippet="  def load_item(item_id:  int)  -> dict:  "),
          Evidence(file=SERVICE, start_line=1, end_line=1,
                   snippet="    2|     return {\"id\": item_id}"),
          Evidence(file=SERVICE, start_line=5, end_line=6)]
    assert evidence_problems(ok, fs) == []
    assert evidence_problems([Evidence(file="app/nope.py", start_line=1, end_line=1)], fs)
    assert evidence_problems([Evidence(file=SERVICE, start_line=40, end_line=41)], fs)
    assert evidence_problems([Evidence(file=SERVICE, start_line=1, end_line=1,
                                       snippet="os.system(cmd)")], fs)
    assert evidence_problems([Evidence(file="../etc/passwd", start_line=1, end_line=1)], fs)


def test_fp_without_valid_evidence_becomes_needs_review(tmp_path):
    ctx = context(tmp_path, [finding("r1", 1), finding("r2", 5), finding("r3", 10)])
    out = _outcome(verdicts=[
        verdict("F1", "FP", evidence=[{"file": "app/nope.py", "start_line": 1, "end_line": 1}]),
        verdict("F2", "FP", evidence=[{"file": SERVICE, "start_line": 5, "end_line": 5,
                                       "snippet": "sanitize(data)  # an toàn"}]),
        verdict("F3", "FP", evidence=[]),
    ])
    entries = build_entries(ctx.clusters, out, ctx.fs)
    assert [e.verdict for e in entries] == ["NEEDS_REVIEW"] * 3
    reasons = sorted(e.reasoning for e in entries)
    assert sum(r.startswith("[Bằng chứng không khớp mã nguồn") for r in reasons) == 2
    assert sum(r.startswith("[Kết luận FP không có bằng chứng]") for r in reasons) == 1


def test_tp_with_valid_evidence_kept(tmp_path):
    ctx = context(tmp_path, [finding("r1", 1)])
    (entry,) = build_entries(ctx.clusters, _outcome(verdicts=[verdict("F1")]), ctx.fs)
    assert entry.verdict == "TP" and entry.reasoning == "lý do"


def _new(file=ROUTER, line=22, cwe="CWE-639", snippet="def export(") -> dict:
    return {"title": "IDOR", "severity": "HIGH", "confidence": 0.8, "cwe": cwe,
            "reasoning": "thiếu kiểm tra quyền",
            "evidence": [{"file": file, "start_line": line, "end_line": line,
                          "snippet": snippet}]}


def test_hallucinated_new_finding_downgraded(tmp_path):
    ctx = context(tmp_path, [])
    (entry,) = build_entries(ctx.clusters, _outcome(new=[_new(file="app/nope.py")]), ctx.fs)
    assert entry.verdict == "NEEDS_REVIEW" and entry.source == "agent"
    assert entry.finding_ids == [] and entry.finding_id == "agent:1"


def test_new_finding_duplicating_cluster_dropped(tmp_path):
    ctx = context(tmp_path, [finding("sqli", 1, cwes=["CWE-89"])])
    dup = _new(file=SERVICE, line=2, cwe="CWE-89", snippet="return")
    entries = build_entries(ctx.clusters, _outcome(new=[dup, _new()]), ctx.fs)
    agent = [e for e in entries if e.source == "agent"]
    assert len(entries) == 2 and len(agent) == 1
    assert agent[0].finding_id == "agent:1" and agent[0].verdict == "TP"
    assert (agent[0].file, agent[0].line) == (ROUTER, 22)


def test_cluster_entry_fields(tmp_path):
    ctx = context(tmp_path, [finding("sqli-a", 1, "semgrep", "HIGH", ["CWE-89"]),
                             finding("B608", 1, "bandit", "LOW", ["CWE-89"]),
                             finding("py/sql-injection", 1, "codeql", "HIGH", ["CWE-89"])])
    (entry,) = build_entries(ctx.clusters, _outcome(verdicts=[verdict("F1", severity="CRITICAL",
                                                                      cwe="CWE-89")]), ctx.fs)
    assert entry.source == "semgrep" and entry.title == "sqli-a (semgrep)"
    assert entry.finding_ids == ctx.clusters[0].ids and len(entry.finding_ids) == 3
    assert entry.finding_id == f"semgrep:sqli-a:{SERVICE}:1"
    assert (entry.file, entry.line, entry.severity, entry.cwe) == (SERVICE, 1, "CRITICAL",
                                                                    "CWE-89")


def test_uncovered_never_fp_and_order(tmp_path):
    ctx = context(tmp_path, [finding("a", 1, sev="LOW"), finding("b", 5), finding("c", 10)])
    out = _outcome(verdicts=[verdict("F3", "FP", evidence=[
        {"file": SERVICE, "start_line": 10, "end_line": 10,
         "snippet": "def run(self, data: dict) -> str:"}])],
        new=[_new()])
    out.limit_hit = True
    entries = build_entries(ctx.clusters, out, ctx.fs)
    assert [e.verdict for e in entries] == ["TP", "NEEDS_REVIEW", "NEEDS_REVIEW", "FP"]
    assert [e.severity for e in entries[1:3]] == ["HIGH", "LOW"]
    assert "giới hạn" in entries[1].reasoning


def test_fp_evidence_must_quote_the_flagged_code(tmp_path):
    """Final review I2: an FP for a HIGH finding cannot rest on unrelated or trivial evidence."""
    ctx = context(tmp_path, [finding("sqli", 1, cwes=["CWE-89"])])
    far = verdict("F1", "FP", evidence=[{"file": "docs/security-requirements.md",
                                         "start_line": 1, "end_line": 1}])
    tiny = verdict("F1", "FP", evidence=[{"file": SERVICE, "start_line": 1, "end_line": 1,
                                          "snippet": ")"}])
    good = verdict("F1", "FP", evidence=[{"file": SERVICE, "start_line": 1, "end_line": 2,
                                          "snippet": 'return {"id": item_id}'}])
    for v, expected in ((far, "NEEDS_REVIEW"), (tiny, "NEEDS_REVIEW"), (good, "FP")):
        (entry,) = build_entries(ctx.clusters, _outcome(verdicts=[v]), ctx.fs)
        assert entry.verdict == expected, v["evidence"]


def test_fp_evidence_in_related_file_or_for_sca(tmp_path):
    flow = ScanFinding("codeql", "py/sql-injection", "HIGH", SERVICE, 1, 1, "m", ("CWE-89",),
                       (ROUTER,))
    trivy = finding("CVE-2020-14343", 1, tool="trivy", cwes=["CWE-1395"], file="app/uv.lock")
    ctx = context(tmp_path, [flow, trivy])
    ids = {c.findings[0].tool: c.id for c in ctx.clusters}
    out = _outcome(verdicts=[
        verdict(ids["codeql"], "FP", evidence=[{"file": ROUTER, "start_line": 13, "end_line": 13,
                                                "snippet": "return service.load_item(item_id)"}]),
        verdict(ids["trivy"], "FP", evidence=[{
            "file": "app/medicare/demo/importer.py", "start_line": 5, "end_line": 5,
            "snippet": "return yaml.safe_load(text)"}]),
    ])
    assert [e.verdict for e in build_entries(ctx.clusters, out, ctx.fs)] == ["FP", "FP"]
