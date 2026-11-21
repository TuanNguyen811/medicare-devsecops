from test_cli import SERVICE, scenario

from secagent.stages import prepare
from secagent.trace import Trace


def test_prepare_matches_cli_clusters(tmp_path):
    repo, base, head, sarif_dir, line = scenario(tmp_path)
    p = prepare(repo, base, head, sarif_dir, "docs/security-requirements.md", True, Trace(None))
    assert [c.id for c in p.clusters] == ["F1"]
    assert p.clusters[0].ids == sorted([f"codeql:py/sql-injection:{SERVICE}:{line}",
                                        f"semgrep:medicare.sqlalchemy-text-fstring:{SERVICE}:{line}"])
    assert p.requirements is not None and SERVICE in p.diff.changed


def test_prepare_without_requirements(tmp_path):
    repo, base, head, sarif_dir, _ = scenario(tmp_path)
    p = prepare(repo, base, head, sarif_dir, "docs/security-requirements.md", False, Trace(None))
    assert p.requirements is None
