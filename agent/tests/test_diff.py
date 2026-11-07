import pytest
from fakes import commit_all, git, make_git_repo, write_files

from secagent.context.diff import load_diff, parse_unified_diff

SAMPLE = """\
diff --git a/app/a.py b/app/a.py
index 1111111..2222222 100644
--- a/app/a.py
+++ b/app/a.py
@@ -1,3 +1,4 @@
 x = 1
+y = 2
 z = 3
 w = 4
@@ -10,3 +11,4 @@ def f():
 a
--- comment that was removed
+c
+++ comment that was added
diff --git a/app/new.py b/app/new.py
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/app/new.py
@@ -0,0 +1,2 @@
+one
+two
diff --git a/app/old.py b/app/old.py
deleted file mode 100644
index 4444444..0000000
--- a/app/old.py
+++ /dev/null
@@ -1,2 +0,0 @@
-gone
-gone too
"""


def test_parse_unified_diff_added_lines():
    d = parse_unified_diff(SAMPLE)
    assert d.changed == {"app/a.py", "app/new.py", "app/old.py"}
    assert d.files["app/a.py"].added == {2, 12, 13}
    assert d.files["app/new.py"].added == {1, 2}
    assert d.files["app/old.py"].added == set()
    assert "+y = 2" in d.files["app/a.py"].patch and "+two" not in d.files["app/a.py"].patch
    assert "+one" in d.text()


def test_diff_text_is_truncated_and_redacted():
    secret = "AKIA" + "Z" * 16
    body = "".join(f"+line {i}\n" for i in range(50))
    d = parse_unified_diff(
        "diff --git a/k.py b/k.py\n--- a/k.py\n+++ b/k.py\n@@ -0,0 +1,51 @@\n"
        f'+key = "{secret}"\n' + body)
    assert secret not in d.text()
    short = d.text(max_lines=10)
    assert len(short.splitlines()) == 11 and "get_diff(path)" in short.splitlines()[-1]


def test_load_diff_uses_merge_base(tmp_path):
    repo = make_git_repo(tmp_path, {"README.md": "x\n"})
    git(repo, "switch", "-q", "-c", "feature")
    write_files(repo, {"app/bệnh nhân.py": "a = 1\nb = 2\n"})
    head = commit_all(repo, "feature")
    git(repo, "switch", "-q", "main")
    write_files(repo, {"infra/main.tf": "resource {}\n"})
    base = commit_all(repo, "main moved on")
    d = load_diff(repo, base, head)
    assert d.changed == {"app/bệnh nhân.py"}
    assert d.files["app/bệnh nhân.py"].added == {1, 2}


def test_load_diff_rejects_option_like_revisions(tmp_path):
    with pytest.raises(ValueError):
        load_diff(tmp_path, "--output=/tmp/x", "HEAD")


def test_mask_lines_hides_gitleaks_lines_in_the_patch():
    d = parse_unified_diff(SAMPLE).mask_lines({"app/a.py": {2}, "app/new.py": {1}})
    assert "y = 2" not in d.files["app/a.py"].patch and "Gitleaks" in d.files["app/a.py"].patch
    assert "+one" not in d.text() and "+two" in d.text()
    assert d.files["app/a.py"].added == {2, 12, 13}
