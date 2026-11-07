"""Dependency reachability helper for SCA findings: locked version + where it is imported."""

from __future__ import annotations

import re
import tomllib

from secagent.tools.fs import RepoFS, ToolError

MODULE_ALIASES = {
    "pyyaml": "yaml",
    "pillow": "PIL",
    "beautifulsoup4": "bs4",
    "python-jose": "jose",
    "pyjwt": "jwt",
    "python-multipart": "multipart",
}


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def get_dependency_usage(fs: RepoFS, package: str, lock: str = "app/uv.lock") -> str:
    name = _normalize(package)
    try:
        data = tomllib.loads("\n".join(fs.lines(lock)))
    except (ToolError, tomllib.TOMLDecodeError):
        data = {}
    versions = [str(p.get("version", "?")) for p in data.get("package", [])
                if _normalize(str(p.get("name", ""))) == name]
    module = MODULE_ALIASES.get(name, name.replace("-", "_"))
    pattern = re.compile(rf"^\s*(from\s+{re.escape(module)}[\.\s]|import\s+{re.escape(module)}\b)")
    sites = []
    for rel in fs.files():
        if not rel.endswith(".py"):
            continue
        try:
            lines = fs.lines(rel)
        except ToolError:
            continue
        sites += [f"{rel}:{n}: {line.strip()}" for n, line in enumerate(lines, start=1)
                  if pattern.search(line)]
    lines_out = [
        f"{name} {', '.join(versions)} (trong {lock})" if versions
        else f"{name}: không có trong {lock}",
        f"module: {module}",
    ]
    lines_out += [f"Nơi import ({len(sites)}):", *sites[:50]] if sites else ["không có nơi import"]
    return "\n".join(lines_out)
