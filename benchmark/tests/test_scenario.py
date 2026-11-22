import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scenario as sc


def write(path: Path, **meta) -> Path:
    path.mkdir(parents=True)
    lines = [f"{k}: {v}" for k, v in meta.items()]
    (path / "scenario.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_fake_secrets_are_deterministic_and_shaped():
    text = "a=@@FAKE:aws-key-id:main@@ b=@@FAKE:hex64:jwt@@ c=@@FAKE:sk-live:pay@@"
    once, again = sc.expand_fakes(text, "S08"), sc.expand_fakes(text, "S08")
    assert once == again and "@@" not in once
    assert once != sc.expand_fakes(text, "S03")  # another scenario, other values
    key = once.split()[0][2:]
    assert key.startswith("AKIA") and len(key) == 20 and key[4:].isalnum()
    assert len(once.split()[1][2:]) == 64 and once.split()[2][2:].startswith("sk_live_")
    with pytest.raises(sc.ScenarioError):
        sc.expand_fakes("@@FAKE:nope:x@@", "S01")


def test_scenario_metadata_is_validated(tmp_path):
    ok = sc.load(write(tmp_path / "S01-search", id="S01", title="t", split="dev",
                       kind="vuln", commit_message="m"))
    assert (ok.id, ok.split, ok.kind, ok.patch_text(), ok.touches_app()) == (
        "S01", "dev", "vuln", "", False)
    for bad in ({"id": "S1"}, {"split": "train"}, {"kind": "bug"}, {"title": ""}):
        meta = {"id": "S02", "title": "t", "split": "dev", "kind": "vuln",
                "commit_message": "m", **bad}
        with pytest.raises(sc.ScenarioError):
            sc.load(write(tmp_path / f"S02-x{len(list(tmp_path.iterdir()))}", **meta))


def test_touched_paths_and_matrix(tmp_path, monkeypatch):
    app = write(tmp_path / "S01-app", id="S01", title="t", split="dev", kind="vuln",
                commit_message="m")
    (app / "patch.diff").write_text("--- a/app/x.py\n+++ b/app/x.py\n@@ -1 +1 @@\n-a\n+b\n",
                                    encoding="utf-8")
    iac = write(tmp_path / "S10-iac", id="S10", title="t", split="dev", kind="vuln",
                commit_message="m")
    (iac / "patch.diff").write_text("--- a/infra/k8s/d.yaml\n+++ b/infra/k8s/d.yaml\n",
                                    encoding="utf-8")
    write(tmp_path / "S00-baseline", id="S00", title="t", split="test", kind="baseline",
          commit_message="m")
    monkeypatch.setattr(sc, "SCENARIOS", tmp_path)
    m = sc.matrix(sc.select("all"))
    assert m["scan"] == ["S00", "S01", "S10"]
    assert {d["id"] for d in m["dast"]} == {"S00", "S01"} and len(m["dast"]) == 10
    assert [s.id for s in sc.select("dev")] == ["S00", "S01", "S10"]
    assert [s.id for s in sc.select("S01, S01,S10")] == ["S01", "S10"]
    with pytest.raises(sc.ScenarioError):
        sc.select("S99")


def test_deletions_and_compose_changes_need_their_own_dast(tmp_path):
    gone = write(tmp_path / "S02-gone", id="S02", title="t", split="dev", kind="vuln",
                 commit_message="m")
    (gone / "patch.diff").write_text("--- a/app/medicare/x.py\n+++ /dev/null\n",
                                     encoding="utf-8")
    compose = write(tmp_path / "S03-compose", id="S03", title="t", split="dev", kind="vuln",
                    commit_message="m")
    (compose / "patch.diff").write_text(
        "--- a/infra/docker-compose.yml\n+++ b/infra/docker-compose.yml\n", encoding="utf-8")
    assert sc.load(gone).touched() == ["app/medicare/x.py"] and sc.load(gone).touches_app()
    assert sc.load(compose).touches_app()


def _has_base() -> bool:
    return subprocess.run(["git", "cat-file", "-e", f"{sc.base_commit()}^{{commit}}"],
                          check=False, cwd=sc.HERE, capture_output=True).returncode == 0


@pytest.mark.skipif(not _has_base(), reason="BASE_COMMIT not in this clone (shallow checkout)")
def test_materialize_is_deterministic_and_sanitized(tmp_path):
    (s00,) = sc.select("S00")
    repo = sc.HERE.parent
    first = sc.materialize(s00, tmp_path / "a", repo)
    try:
        second = sc.materialize(s00, tmp_path / "b", repo)
        assert first == second
        for path in sc.SANITIZED:
            assert not (tmp_path / "a" / path).exists()
        assert (tmp_path / "a" / "docs" / "security-requirements.md").is_file()
        assert (tmp_path / "a" / "app" / "medicare").is_dir()
        # Nothing in the tree the agent reads may describe the experiment or its answers.
        leaks = subprocess.run(
            ["git", "grep", "-n", "-i", "-E", LEAK, "--", ".", ":!app/medicare/seed.py"],
            check=False, cwd=tmp_path / "a", capture_output=True, text=True, encoding="utf-8")
        assert leaks.stdout == ""
        status = subprocess.run(["git", "status", "--porcelain"], check=True,
                                cwd=tmp_path / "a", capture_output=True, text=True)
        assert status.stdout == ""
    finally:
        for name in ("a", "b"):
            subprocess.run(["git", "worktree", "remove", "--force", str(tmp_path / name)],
                           check=False, cwd=repo, capture_output=True)


LEAK = r"benchmark|kịch bản|ground.?truth|báo nhầm|planted"
# A patch that edits an existing file and adds one with a fake secret. Its SHAs are pinned:
# Linux CI and the Windows machine that runs the agent must build the very same commits.
GOLDEN_PATCH = "\n".join([
    "--- a/app/medicare/validators.py",
    "+++ b/app/medicare/validators.py",
    "@@ -1,4 +1,4 @@",
    '-"""Format validators and display helpers for Vietnamese identifiers."""',
    '+"""Format validators and display helpers for Vietnamese identifiers (v2)."""',
    " ",
    " import re",
    " from decimal import Decimal",
    "--- /dev/null",
    "+++ b/app/medicare/sms_config.py",
    "@@ -0,0 +1,2 @@",
    '+SMS_API_KEY = "@@FAKE:hex32:sms@@"',
    '+SENDER = "MediCare"',
    "",
])
GOLDEN = {"base": "b947d5c04078cd0eb525b9dc5d0271f65e3dcfa6",
          "head": "ea19eacfd5601487f3af3d70838da7066f16d6c1"}


@pytest.mark.skipif(not _has_base(), reason="BASE_COMMIT not in this clone (shallow checkout)")
def test_materialize_golden_shas_and_cleanup_on_failure(tmp_path):
    golden = write(tmp_path / "scn" / "S98-golden", id="S98", title="t", split="dev",
                   kind="vuln", commit_message="Thêm cấu hình gửi SMS nhắc lịch")
    (golden / "patch.diff").write_bytes(GOLDEN_PATCH.encode("utf-8"))
    broken = write(tmp_path / "scn" / "S97-broken", id="S97", title="t", split="dev",
                   kind="vuln", commit_message="m")
    (broken / "patch.diff").write_bytes(b"--- a/nope.py\n+++ b/nope.py\n@@ -1 +1 @@\n-x\n+y\n")
    repo = sc.HERE.parent
    try:
        result = sc.materialize(sc.load(golden), tmp_path / "g", repo)
        assert {k: result[k] for k in GOLDEN} == GOLDEN
        text = (tmp_path / "g" / "app" / "medicare" / "sms_config.py").read_bytes()
        assert b"\r" not in text and b"@@FAKE" not in text
        with pytest.raises(sc.ScenarioError):
            sc.materialize(sc.load(broken), tmp_path / "b", repo)
        assert not (tmp_path / "b").exists()  # a failed build leaves nothing behind
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", str(tmp_path / "g")],
                       check=False, cwd=repo, capture_output=True)


def test_real_scenarios_load():
    scenarios = sc.all_scenarios()
    assert scenarios and scenarios[0].id == sc.BASELINE
    for s in scenarios:
        assert (s.dir / "ground_truth.yaml").is_file(), s.id
