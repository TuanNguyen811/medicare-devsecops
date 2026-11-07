from fakes import miniapp_repo

from secagent.tools.deps import get_dependency_usage
from secagent.tools.fs import RepoFS


def test_dependency_usage_reports_version_and_imports(tmp_path):
    fs = RepoFS(miniapp_repo(tmp_path))
    out = get_dependency_usage(fs, "PyYAML")
    assert "pyyaml 5.3.1" in out and "module: yaml" in out
    assert "app/medicare/demo/importer.py:1: import yaml" in out


def test_dependency_not_in_lock_or_unused(tmp_path):
    fs = RepoFS(miniapp_repo(tmp_path))
    out = get_dependency_usage(fs, "requests")
    assert "không có trong app/uv.lock" in out and "không có nơi import" in out
    assert "fastapi 0.115.0" in get_dependency_usage(fs, "fastapi")
