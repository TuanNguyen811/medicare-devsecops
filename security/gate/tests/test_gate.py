import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from gate import (
    Finding,
    SarifError,
    changed_from_git,
    decide,
    filter_changed,
    load_all,
    load_sarif,
    normalize_path,
    render_summary,
    severity_of,
)

FIX = Path(__file__).parent / "fixtures"
GATE = Path(__file__).resolve().parents[1] / "gate.py"
SQLI = "semgrep:medicare.sqlalchemy-text-fstring:app/medicare/patient/service.py:42"


def f(tool="semgrep", rule="r1", sev="HIGH", file="app/a.py", line=3):
    return Finding(tool, rule, sev, file, line)


def verdict(ids, v, sev="HIGH", source="semgrep", confidence=0.9):
    return {"finding_ids": ids, "verdict": v, "severity": sev, "source": source,
            "confidence": confidence}


# --- parsing -----------------------------------------------------------------


def test_finding_id_format():
    assert f().id == "semgrep:r1:app/a.py:3"


@pytest.mark.parametrize("uri,ws,expected", [
    ("file:///github/workspace/app/a.py", None, "app/a.py"),
    ("/github/workspace/infra/main.tf", None, "infra/main.tf"),
    ("/home/runner/work/x/x/infra/main.tf", "/home/runner/work/x/x", "infra/main.tf"),
    ("./app/b.py", None, "app/b.py"),
    ("app\\c.py", None, "app/c.py"),
    ("app/medicare/my%20tool.py", None, "app/medicare/my tool.py"),
    ("file:///github/workspace/app/b%E1%BB%87nh%20nh%C3%A2n.py", None, "app/bệnh nhân.py"),
])
def test_normalize_path(uri, ws, expected):
    assert normalize_path(uri, ws) == expected


@pytest.mark.parametrize("score,sev", [
    ("9.8", "CRITICAL"), ("9.0", "CRITICAL"), ("7.0", "HIGH"), ("5.3", "MEDIUM"), ("1.0", "LOW"),
])
def test_security_severity_from_rule(score, sev):
    assert severity_of({}, {"properties": {"security-severity": score}}, "codeql") == sev


def test_result_security_severity_wins_over_rule():
    result = {"properties": {"security-severity": "9.5"}}
    assert severity_of(result, {"properties": {"security-severity": "2.0"}}, "trivy") == "CRITICAL"


def test_level_fallback_and_gitleaks_always_high():
    assert severity_of({"level": "error"}, None, "semgrep") == "HIGH"
    assert severity_of({"level": "warning"}, None, "semgrep") == "MEDIUM"
    assert severity_of({}, {"defaultConfiguration": {"level": "note"}}, "semgrep") == "LOW"
    assert severity_of({}, None, "semgrep") == "LOW"
    assert severity_of({"level": "note"}, None, "gitleaks") == "HIGH"


def test_loads_each_tool_shape():
    sem = load_sarif(FIX / "semgrep.sarif", "semgrep", None)
    assert sem[0].id == SQLI and [x.severity for x in sem] == ["HIGH", "MEDIUM"]
    trivy = load_sarif(FIX / "trivy.sarif", "trivy", None)
    assert trivy == [Finding("trivy", "CVE-2020-14343", "CRITICAL", "app/uv.lock", 1)]
    chk = load_sarif(FIX / "checkov.sarif", "checkov", None)
    assert chk[0].file == "infra/terraform/main.tf"


def test_rule_lookup_by_rule_index():
    codeql = load_sarif(FIX / "codeql.sarif", "codeql", None)
    assert [(x.rule_id, x.severity, x.file) for x in codeql] == [
        ("py/sql-injection", "HIGH", "app/medicare/patient/service.py"),
        ("py/clear-text-logging-sensitive-data", "CRITICAL", "app/medicare/auth/router.py"),
    ]


def test_result_without_location_is_kept():
    found = load_sarif(FIX / "nolocation.sarif", "x", None)
    assert found == [Finding("x", "repo-wide-issue", "HIGH", "", 0)]
    assert filter_changed(found, {"app/other.py"}) == found


def test_corrupt_sarif_raises():
    with pytest.raises(SarifError):
        load_sarif(FIX / "corrupt.sarif", "x", None)


def test_missing_dir_or_file_means_no_findings(tmp_path):
    assert load_all(tmp_path / "nope", None) == ([], [])
    assert load_all(tmp_path, None) == ([], [])


def test_load_all_names_tool_after_file_and_reports_corrupt(tmp_path):
    shutil.copy(FIX / "gitleaks.sarif", tmp_path)
    shutil.copy(FIX / "corrupt.sarif", tmp_path)
    findings, errors = load_all(tmp_path, None)
    assert [x.tool for x in findings] == ["gitleaks"] and errors == ["corrupt.sarif"]


def test_filter_changed_keeps_only_changed_files():
    a, b = f(file="app/a.py"), f(file="app/b.py")
    assert filter_changed([a, b], {"app/b.py"}) == [b]


def test_filter_changed_keeps_commit_scoped_gitleaks_findings():
    """Gitleaks scans only the PR's commits and reports the path of the commit that added the
    secret, so a secret committed and then renamed or deleted is not in the tree diff."""
    leak = f(tool="gitleaks", rule="aws-access-token", file="app/x.py")
    other = f(tool="semgrep", file="app/x.py")
    assert filter_changed([leak, other], {"app/y.py"}) == [leak]


def test_flow_through_a_changed_file_keeps_the_finding():
    """CodeQL reports a path-problem at the sink; the PR may only have added the source."""
    flow, related = load_sarif(FIX / "codeflow.sarif", "codeql", None)
    assert flow.id == "codeql:py/sql-injection:app/medicare/common/db.py:12"
    assert filter_changed([flow], {"app/medicare/patient/router.py"}) == [flow]
    assert filter_changed([related], {"app/medicare/billing/router.py"}) == [related]
    assert filter_changed([flow, related], {"app/medicare/auth/router.py"}) == []


def test_terraform_directory_is_one_unit():
    """Checkov evaluates variables, so editing variables.tf surfaces findings in main.tf."""
    x = f(tool="checkov", rule="CKV_AWS_24", file="infra/terraform/main.tf")
    assert filter_changed([x], {"infra/terraform/variables.tf"}) == [x]
    assert filter_changed([x], {"infra/k8s/deployment.yaml", "infra/main.tf"}) == []


def test_results_with_in_source_suppressions_still_count(tmp_path):
    """Pin: Checkov keeps `checkov:skip` results in SARIF with `suppressions`; they still count."""
    doc = {"runs": [{"tool": {"driver": {"name": "checkov"}}, "results": [{
        "ruleId": "CKV_AWS_18", "level": "error",
        "suppressions": [{"kind": "inSource", "justification": "demo"}],
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "infra/x.tf"},
                                            "region": {"startLine": 1}}}]}]}]}
    (tmp_path / "checkov.sarif").write_text(json.dumps(doc))
    assert load_sarif(tmp_path / "checkov.sarif", "checkov", None) == [
        Finding("checkov", "CKV_AWS_18", "HIGH", "infra/x.tf", 1)]


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True, encoding="utf-8").stdout.strip()


def _commit(repo, path, text="x = 1\n"):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    _git(repo, "add", "--all")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", path)
    return _git(repo, "rev-parse", "HEAD")


def test_changed_from_git_uses_the_merge_base_and_plain_names(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _commit(repo, "README.md")
    _git(repo, "switch", "-q", "-c", "feature")
    head = _commit(repo, "app/bệnh nhân.py")
    _git(repo, "switch", "-q", "main")
    base = _commit(repo, "infra/terraform/main.tf")  # main moved on after the PR branched
    assert changed_from_git(base, head, repo) == {"app/bệnh nhân.py"}


# --- decisions ---------------------------------------------------------------


def test_corrupt_sarif_blocks():
    d = decide([], mode="traditional", report=None, labels=set(), agent_exit=None,
               errors=["corrupt.sarif"])
    assert d.block


def test_traditional_blocks_high_and_critical_only():
    assert not decide([f(sev="MEDIUM"), f(sev="LOW")], mode="traditional", report=None,
                      labels=set(), agent_exit=None, errors=[]).block
    d = decide([f(sev="HIGH")], mode="traditional", report=None, labels=set(),
               agent_exit=None, errors=[])
    assert d.block and d.mode_used == "traditional" and d.blocking == [f(sev="HIGH").id]


@pytest.mark.parametrize("agent_exit,report", [(2, {"findings": []}), (0, None)])
def test_ai_mode_falls_back_when_agent_failed(agent_exit, report):
    d = decide([f()], mode="ai-assisted", report=report, labels=set(),
               agent_exit=agent_exit, errors=[])
    assert d.block and d.mode_used == "traditional (fallback)"


def test_ai_mode_unreviewed_high_blocks():
    d = decide([f()], mode="ai-assisted", report={"findings": []}, labels=set(),
               agent_exit=0, errors=[])
    assert d.block and d.mode_used == "ai-assisted"


@pytest.mark.parametrize("v", ["TP", "NEEDS_REVIEW"])
def test_ai_mode_tp_or_needs_review_blocks(v):
    report = {"findings": [verdict([f().id], v)]}
    assert decide([f()], mode="ai-assisted", report=report, labels=set(), agent_exit=0,
                  errors=[]).block


def test_ai_mode_fp_unblocks_high_but_not_critical_without_label():
    high, crit = f(sev="HIGH", line=1), f(sev="CRITICAL", line=2)
    report = {"findings": [verdict([high.id, crit.id], "FP")]}
    d = decide([high, crit], mode="ai-assisted", report=report, labels=set(), agent_exit=0,
               errors=[])
    assert d.block and d.blocking == [crit.id] and any(high.id in n for n in d.notes)


def test_ai_mode_critical_fp_with_label_passes():
    crit = f(sev="CRITICAL")
    report = {"findings": [verdict([crit.id], "FP", sev="CRITICAL")]}
    assert not decide([crit], mode="ai-assisted", report=report,
                      labels={"security-reviewed"}, agent_exit=0, errors=[]).block


@pytest.mark.parametrize("confidence,blocks", [(0.8, True), (0.7, True), (0.5, False)])
def test_ai_mode_agent_new_tp_high_blocks(confidence, blocks):
    report = {"findings": [verdict([], "TP", source="agent", confidence=confidence)]}
    assert decide([], mode="ai-assisted", report=report, labels=set(), agent_exit=0,
                  errors=[]).block is blocks


def test_ai_mode_agent_new_medium_does_not_block():
    report = {"findings": [verdict([], "TP", sev="MEDIUM", source="agent")]}
    assert not decide([], mode="ai-assisted", report=report, labels=set(), agent_exit=0,
                      errors=[]).block


@pytest.mark.parametrize("order", [("TP", "FP"), ("FP", "TP"), ("NEEDS_REVIEW", "FP")])
def test_ai_mode_conflicting_verdicts_any_non_fp_wins(order):
    report = {"findings": [verdict([f().id], v) for v in order]}
    assert decide([f()], mode="ai-assisted", report=report, labels=set(), agent_exit=0,
                  errors=[]).block


@pytest.mark.parametrize("path", [
    ".trivyignore", "app/.semgrepignore", ".gitleaksignore", "trivy.yaml", ".checkov.yaml",
    "security/gate/gate.py", "security/semgrep/medicare.yml", ".github/workflows/pr-security.yml",
])
def test_changing_scanner_or_pipeline_config_needs_security_review(path):
    d = decide([], mode="traditional", report=None, labels=set(), agent_exit=None, errors=[],
               changed={path, "app/medicare/patient/service.py"})
    assert d.block and d.blocking == [f"policy:{path}"]
    assert not decide([], mode="ai-assisted", report={"findings": []},
                      labels={"security-reviewed"}, agent_exit=0, errors=[],
                      changed={path}).block


def test_ordinary_changes_are_not_policy_blocked():
    assert not decide([], mode="traditional", report=None, labels=set(), agent_exit=None,
                      errors=[], changed={"app/medicare/patient/service.py", "docs/pipeline.md",
                                          "infra/terraform/main.tf"}).block


# --- output ------------------------------------------------------------------


def test_summary_never_contains_messages():
    findings = load_sarif(FIX / "gitleaks.sarif", "gitleaks", None)
    d = decide(findings, mode="traditional", report=None, labels=set(), agent_exit=None,
               errors=[])
    text = render_summary(d, findings)
    assert "AKIA" not in text and "aws-access-token" in text and "app/medicare/sms.py:5" in text


def _run(*args, cwd=None):
    return subprocess.run([sys.executable, str(GATE), *args], capture_output=True, text=True,
                          check=False, encoding="utf-8", cwd=cwd)


def test_cli_exit_codes(tmp_path):
    sarif = tmp_path / "sarif"
    sarif.mkdir()
    shutil.copy(FIX / "semgrep.sarif", sarif)
    changed = tmp_path / "changed.txt"
    changed.write_text("app/medicare/patient/service.py\n")
    summary = tmp_path / "summary.md"
    r = _run("--sarif-dir", str(sarif), "--changed-files", str(changed), "--mode",
             "traditional", "--summary", str(summary))
    assert r.returncode == 1 and "medicare.sqlalchemy-text-fstring" in summary.read_text("utf-8")
    changed.write_text("README.md\n")
    assert _run("--sarif-dir", str(sarif), "--changed-files", str(changed)).returncode == 0


def test_cli_ai_mode_reads_report_and_labels(tmp_path):
    sarif = tmp_path / "sarif"
    sarif.mkdir()
    shutil.copy(FIX / "semgrep.sarif", sarif)
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": [verdict([SQLI], "FP")]}))
    r = _run("--sarif-dir", str(sarif), "--mode", "ai-assisted", "--report", str(report),
             "--agent-exit", "0", "--labels", "bug,security-reviewed")
    assert r.returncode == 0, r.stdout + r.stderr
    report.write_text("{not json")
    r = _run("--sarif-dir", str(sarif), "--mode", "ai-assisted", "--report", str(report),
             "--agent-exit", "0")
    assert r.returncode == 1 and "fallback" in r.stdout


def test_cli_blocks_secret_committed_then_renamed(tmp_path):
    sarif = tmp_path / "sarif"
    sarif.mkdir()
    shutil.copy(FIX / "gitleaks.sarif", sarif)  # leak reported at app/medicare/sms.py:5
    changed = tmp_path / "changed.txt"
    changed.write_text("app/medicare/notify.py\n")  # the file was renamed in a later commit
    assert _run("--sarif-dir", str(sarif), "--changed-files", str(changed)).returncode == 1


def test_cli_reads_nul_separated_changed_files_and_decodes_sarif_uris(tmp_path):
    sarif = tmp_path / "sarif"
    sarif.mkdir()
    shutil.copy(REAL / "bandit-encoded.sarif", sarif / "bandit.sarif")
    changed = tmp_path / "changed.txt"
    changed.write_bytes("app/medicare/bệnh nhân.py\0app/medicare/my tool.py\0".encode())
    r = _run("--sarif-dir", str(sarif), "--changed-files", str(changed))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "app/medicare/bệnh nhân.py:3" in r.stdout and "app/medicare/my tool.py:3" in r.stdout


def test_cli_computes_changed_files_from_git(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _commit(repo, "README.md")
    _git(repo, "switch", "-q", "-c", "feature")
    head = _commit(repo, "app/medicare/sms.py")
    _git(repo, "switch", "-q", "main")
    base = _commit(repo, "docs/x.md")
    sarif = tmp_path / "sarif"
    sarif.mkdir()
    shutil.copy(FIX / "semgrep.sarif", sarif)  # HIGH finding in app/medicare/patient/service.py
    r = _run("--sarif-dir", str(sarif), "--base", base, "--head", head, cwd=repo)
    assert r.returncode == 0, r.stdout + r.stderr
    shutil.copy(FIX / "gitleaks.sarif", sarif)  # commit-scoped: always counts
    assert _run("--sarif-dir", str(sarif), "--base", base, "--head", head, cwd=repo).returncode == 1


# --- real tool output (v0.1-baseline + infra, scanned with the pinned versions) ---------

REAL = FIX / "real"


@pytest.mark.parametrize("name", ["bandit", "checkov", "codeql", "gitleaks", "semgrep",
                                  "trivy", "zizmor"])
def test_parses_real_tool_output(name):
    findings = load_sarif(REAL / f"{name}.sarif", name, None)
    assert all(x.rule_id != "unknown" and x.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
               for x in findings)


def test_real_codeql_rule_metadata_lives_in_tool_extensions():
    """CodeQL puts rules in tool.extensions[] and references them via rule.toolComponent."""
    (finding,) = load_sarif(REAL / "codeql.sarif", "codeql", None)
    assert finding.rule_id == "py/clear-text-logging-sensitive-data"
    assert finding.severity == "HIGH"  # security-severity 7.5 on the extension rule
    assert finding.file == "app/medicare/seed.py"


def test_real_zizmor_template_injection_in_changed_workflow_blocks():
    """zizmor must run from the repo root so its SARIF paths match the PR's changed files."""
    findings = filter_changed(load_sarif(REAL / "zizmor.sarif", "zizmor", None),
                              {".github/workflows/bad.yml"})
    d = decide(findings, mode="traditional", report=None, labels=set(), agent_exit=None,
               errors=[])
    assert "zizmor:zizmor/template-injection:.github/workflows/bad.yml:11" in d.blocking


def test_real_checkov_paths_are_repo_relative():
    files = {x.file for x in load_sarif(REAL / "checkov.sarif", "checkov", None)}
    assert files == {"infra/terraform/main.tf", "infra/k8s/deployment.yaml"}
