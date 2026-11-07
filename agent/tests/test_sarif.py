import shutil
import sys

import pytest
from fakes import REPO_ROOT

from secagent.context.diff import FileDiff, PrDiff
from secagent.context.sarif import ScanFinding, cluster_findings, load_findings

GATE_DIR = REPO_ROOT / "security" / "gate"
FIX = GATE_DIR / "tests" / "fixtures"
REAL = FIX / "real"


def _gate():
    """The quality gate is the reference implementation of finding ids (Contract 2)."""
    if str(GATE_DIR) not in sys.path:
        sys.path.insert(0, str(GATE_DIR))
    import gate

    return gate


FIXTURES = sorted(p for p in FIX.rglob("*.sarif") if p.name != "corrupt.sarif")


def _load_one(path, tmp_path, tool=None):
    tool = tool or path.stem
    target = tmp_path / path.relative_to(FIX).as_posix().replace("/", "_")
    target.mkdir(exist_ok=True)
    shutil.copy(path, target / f"{tool}.sarif")
    findings, errors = load_findings(target)
    assert errors == []
    return findings


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.relative_to(FIX).as_posix())
def test_ids_match_gate_on_every_fixture(path, tmp_path):
    ours = _load_one(path, tmp_path)
    theirs = _gate().load_sarif(path, path.stem, None)
    assert [(f.id, f.severity) for f in ours] == [(g.id, g.severity) for g in theirs]


def test_corrupt_file_is_reported_not_fatal(tmp_path):
    shutil.copy(FIX / "corrupt.sarif", tmp_path)
    shutil.copy(FIX / "semgrep.sarif", tmp_path)
    findings, errors = load_findings(tmp_path)
    assert errors == ["corrupt.sarif"] and {f.tool for f in findings} == {"semgrep"}
    assert load_findings(tmp_path / "missing") == ([], [])


def test_percent_encoded_paths_are_decoded(tmp_path):
    files = {f.file for f in _load_one(REAL / "bandit-encoded.sarif", tmp_path, "bandit")}
    assert files == {"app/medicare/bệnh nhân.py", "app/medicare/my tool.py"}


def test_cwe_extraction(tmp_path):
    (codeql,) = _load_one(REAL / "codeql.sarif", tmp_path)
    assert {"CWE-312", "CWE-359", "CWE-532"} <= set(codeql.cwes)
    bandit = _load_one(REAL / "bandit.sarif", tmp_path)
    assert {c for f in bandit for c in f.cwes} == {"CWE-330", "CWE-703"}
    leaks = _load_one(REAL / "gitleaks.sarif", tmp_path)
    assert leaks and all(f.cwes == ("CWE-798",) for f in leaks)


def test_gitleaks_message_never_forwarded(tmp_path):
    leaks = _load_one(REAL / "gitleaks.sarif", tmp_path)
    assert all(f.message == f"Gitleaks: {f.rule_id}" for f in leaks)


def test_codeflow_files_are_related(tmp_path):
    flow, related = _load_one(FIX / "codeflow.sarif", tmp_path, "codeql")
    assert flow.file == "app/medicare/common/db.py" and flow.line == 12
    assert flow.related == ("app/medicare/patient/router.py",)
    assert related.related == ("app/medicare/billing/router.py",)


def sf(tool, rule, line, cwes, file="app/svc.py", sev="HIGH"):
    return ScanFinding(tool, rule, sev, file, line, line, "m", tuple(cwes), ())


def test_cluster_merges_tools_on_same_line():
    findings = [
        sf("semgrep", "medicare.sqlalchemy-text-fstring", 55, ["CWE-89"]),
        sf("codeql", "py/sql-injection", 55, ["CWE-89"]),
        sf("bandit", "B608", 56, ["CWE-89"], sev="LOW"),
        sf("bandit", "B101", 57, ["CWE-703"], sev="LOW"),
        sf("semgrep", "medicare.sqlalchemy-text-fstring", 55, ["CWE-89"], file="app/other.py"),
        sf("checkov", "CKV_AWS_356", 15, [], file="infra/main.tf"),
        sf("checkov", "CKV_AWS_109", 15, [], file="infra/main.tf"),
    ]
    clusters = cluster_findings(findings, PrDiff({}))
    by_file = [(c.id, c.file, c.line, len(c.ids)) for c in clusters]
    assert by_file == [
        ("F1", "app/other.py", 55, 1),
        ("F2", "app/svc.py", 55, 3),
        ("F3", "app/svc.py", 57, 1),
        ("F4", "infra/main.tf", 15, 1),
        ("F5", "infra/main.tf", 15, 1),
    ]
    sqli = clusters[1]
    assert sqli.severity == "HIGH" and sqli.tools == ["bandit", "codeql", "semgrep"]
    assert sqli.ids == sorted(sqli.ids) and sqli.cwes == ["CWE-89"]


def test_cluster_ids_follow_sorted_order():
    findings = [sf("x", "r", 9, [], file="b.py"), sf("x", "r", 1, [], file="a.py"),
                sf("x", "repo-wide", 0, [], file=""), sf("x", "repo-wide2", 0, [], file="")]
    clusters = cluster_findings(findings, PrDiff({}))
    assert [(c.id, c.file) for c in clusters] == [("F1", ""), ("F2", ""), ("F3", "a.py"),
                                                   ("F4", "b.py")]


def test_in_diff_flag():
    diff = PrDiff({"app/svc.py": FileDiff("app/svc.py", {55}),
                   "app/uv.lock": FileDiff("app/uv.lock", {10})})
    clusters = cluster_findings([
        sf("semgrep", "a", 55, ["CWE-89"]),
        sf("semgrep", "b", 70, ["CWE-79"]),
        sf("gitleaks", "generic-api-key", 3, ["CWE-798"], file="app/renamed_away.py"),
        sf("trivy", "CVE-2020-14343", 1, ["CWE-1395"], file="app/uv.lock"),
        sf("bandit", "B101", 5, ["CWE-703"], file="app/untouched.py"),
    ], diff)
    flags = {c.findings[0].rule_id: c.in_diff for c in clusters}
    assert flags == {"a": True, "b": False, "generic-api-key": True, "CVE-2020-14343": True,
                     "B101": False}
