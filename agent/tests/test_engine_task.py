import json

from fakes import commit_all, git, make_git_repo, miniapp_repo, write_files
from test_cli import scenario

from secagent.cli import main_prepare
from secagent.context.diff import TRUNCATED
from secagent.engine.task import ENGINE_TRUNCATED

LEAKED = "zq7XwM2pL9tK4vR8nB3cY6"
KEYS = "app/medicare/demo/keys.py"


def prepare_argv(repo, base, head, sarif_dir, out, *extra):
    return ["--repo", str(repo), "--base", base, "--head", head, "--sarif-dir", str(sarif_dir),
            "--requirements", "docs/security-requirements.md", "--out", str(out), *extra]


def sarif_doc(tool, results):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": tool, "rules": [{"id": "r1"}]}},
        "results": [{"ruleId": "r1", "level": "error", "message": {"text": message},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": file},
                                                         "region": {"startLine": line}}}]}
                    for file, line, message in results]}]}


def test_prepare_cli_writes_context(tmp_path):
    repo, base, head, sarif_dir, _ = scenario(tmp_path)
    out = tmp_path / "out"
    assert main_prepare(prepare_argv(repo, base, head, sarif_dir, out)) == 0
    ctx = out / "context"
    for name in ("findings.json", "diff.patch", "requirements.md", "task.md"):
        assert (ctx / name).is_file(), name
    findings = json.loads((ctx / "findings.json").read_text(encoding="utf-8"))
    assert findings[0]["cluster_id"] == "F1"
    assert findings[0]["tools"] == ["codeql", "semgrep"] and findings[0]["in_diff"] is True
    task = (ctx / "task.md").read_text(encoding="utf-8")
    assert "F1" in task and "<untrusted-code" in task and '"verdicts"' in task
    assert "{findings_table}" not in task
    # The engine only has Read/Grep/Glob: no secagent tool names in its task.
    assert "report_finding" not in task and "get_diff" not in task and "new_findings" in task


def test_prepare_no_requirements(tmp_path):
    repo, base, head, sarif_dir, _ = scenario(tmp_path)
    out = tmp_path / "out"
    assert main_prepare(prepare_argv(repo, base, head, sarif_dir, out, "--no-requirements")) == 0
    assert not (out / "context" / "requirements.md").exists()
    assert "không cung cấp tài liệu quy tắc" in (out / "context" / "task.md").read_text(
        encoding="utf-8")


def test_mask_worktree_hides_gitleaks_lines(tmp_path):
    repo = miniapp_repo(tmp_path)
    base = git(repo, "rev-parse", "HEAD")
    write_files(repo, {KEYS: f'import os\n\nAPI_KEY = "{LEAKED}"\nOTHER = 1\n'})
    head = commit_all(repo, "thêm khóa")
    sarif_dir = tmp_path / "sarif"
    sarif_dir.mkdir()
    (sarif_dir / "gitleaks.sarif").write_text(json.dumps(sarif_doc("gitleaks", [(KEYS, 3, "x")])))
    out = tmp_path / "out"
    assert main_prepare(prepare_argv(repo, base, head, sarif_dir, out, "--mask-worktree")) == 0
    on_disk = (repo / KEYS).read_text(encoding="utf-8")
    assert LEAKED not in on_disk and "OTHER = 1" in on_disk and "import os" in on_disk
    for name in ("task.md", "diff.patch", "findings.json"):
        assert LEAKED not in (out / "context" / name).read_text(encoding="utf-8"), name


def test_worktree_untouched_without_mask_flag(tmp_path):
    repo = miniapp_repo(tmp_path)
    base = git(repo, "rev-parse", "HEAD")
    write_files(repo, {KEYS: f'API_KEY = "{LEAKED}"\n'})
    head = commit_all(repo, "thêm khóa")
    sarif_dir = tmp_path / "sarif"
    sarif_dir.mkdir()
    (sarif_dir / "gitleaks.sarif").write_text(json.dumps(sarif_doc("gitleaks", [(KEYS, 1, "x")])))
    assert main_prepare(prepare_argv(repo, base, head, sarif_dir, tmp_path / "out")) == 0
    assert LEAKED in (repo / KEYS).read_text(encoding="utf-8")


def test_large_pr_task_is_bounded(tmp_path):
    repo = make_git_repo(tmp_path, {"README.md": "x\n"})
    base = git(repo, "rev-parse", "HEAD")
    big = "".join(f"value_{i} = {i}\n" for i in range(2000))
    write_files(repo, {"app/big.py": big})
    head = commit_all(repo, "pr lớn")
    sarif_dir = tmp_path / "sarif"
    sarif_dir.mkdir()
    (sarif_dir / "semgrep.sarif").write_text(json.dumps(sarif_doc(
        "semgrep", [("app/big.py", 10 + 40 * i, f"finding {i}") for i in range(40)])))
    out = tmp_path / "out"
    assert main_prepare(prepare_argv(repo, base, head, sarif_dir, out, "--no-requirements")) == 0
    ctx = out / "context"
    task = (ctx / "task.md").read_text(encoding="utf-8")
    assert ENGINE_TRUNCATED in task and TRUNCATED not in task
    assert "out/context/diff.patch" in ENGINE_TRUNCATED
    assert len(json.loads((ctx / "findings.json").read_text(encoding="utf-8"))) == 40
    assert len((ctx / "diff.patch").read_text(encoding="utf-8").splitlines()) > 2000


def test_prepare_crash_exits_2(tmp_path, capsys):
    repo, _, head, sarif_dir, _ = scenario(tmp_path)
    bad_base = "0" * 40
    assert main_prepare(prepare_argv(repo, bad_base, head, sarif_dir, tmp_path / "out")) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_prepare_out_not_creatable_exits_2(tmp_path, capsys):
    repo, base, head, sarif_dir, _ = scenario(tmp_path)
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    assert main_prepare(prepare_argv(repo, base, head, sarif_dir, blocker / "out")) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_mask_worktree_counts_lines_by_newline_only(tmp_path):
    repo = miniapp_repo(tmp_path)
    base = git(repo, "rev-parse", "HEAD")
    odd = "ODD = 'a\x0cb\u2028c\x85d'\r\n"
    text = f'{odd}import os\r\nAPI_KEY = "{LEAKED}"\r\nOTHER = 1\r\n'
    target = repo / KEYS
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(text.encode("utf-8"))
    head = commit_all(repo, "thêm khóa")
    sarif_dir = tmp_path / "sarif"
    sarif_dir.mkdir()
    (sarif_dir / "gitleaks.sarif").write_text(json.dumps(sarif_doc("gitleaks", [(KEYS, 3, "x")])))
    out = tmp_path / "out"
    assert main_prepare(prepare_argv(repo, base, head, sarif_dir, out, "--mask-worktree")) == 0
    rows = target.read_bytes().decode("utf-8").split("\n")
    assert rows[0] == odd.rstrip("\n") and rows[1] == "import os\r"
    assert LEAKED not in rows[2] and "REDACTED" in rows[2] and rows[2].endswith("\r")
    assert rows[3] == "OTHER = 1\r"
