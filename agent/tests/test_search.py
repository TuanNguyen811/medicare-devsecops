from fakes import miniapp_repo

from secagent.tools.fs import RepoFS
from secagent.tools.search import search_code


def test_search_code_matches_and_rejects_bad_regex(tmp_path):
    fs = RepoFS(miniapp_repo(tmp_path))
    out = search_code(fs, r"def (load|export)_item")
    assert "app/medicare/demo/service.py:1: def load_item(item_id: int) -> dict:" in out
    assert "app/medicare/demo/service.py:5: def export_item(data: dict) -> str:" in out
    assert out.startswith("<untrusted-code")
    assert "importer.py:1: import yaml" in search_code(fs, r"^import yaml")
    assert "uv.lock" in search_code(fs, r"pyyaml", glob="*.lock")
    assert search_code(fs, "no_such_symbol_anywhere") == "(không có kết quả)"
    assert search_code(fs, "(unclosed").startswith("ERROR")
    assert search_code(fs, "a" * 201).startswith("ERROR")


def test_search_code_stops_at_max_results(tmp_path):
    repo = miniapp_repo(tmp_path, {"many.py": "hit = 1\n" * 80})
    out = search_code(RepoFS(repo), r"^hit", max_results=50)
    assert out.count("many.py:") == 50 and "dừng ở 50 kết quả" in out
