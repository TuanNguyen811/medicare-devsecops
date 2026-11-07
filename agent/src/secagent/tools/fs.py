"""Repository access confined to the repo root; secret files and .git are off limits."""

from __future__ import annotations

import os
import re
import subprocess
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath

from secagent.context.redact import mask_line, redact

MAX_BYTES = 1_000_000
MAX_LINES = 400
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".mypy_cache",
              ".pytest_cache", ".ruff_cache"}
_SECRET_NAME = re.compile(r"^(\.env(\..+)?|id_rsa.*|.*\.(pem|key))$")
_CLOSE_TAG = re.compile(r"<\s*/\s*untrusted-code", re.IGNORECASE)


class ToolError(Exception):
    """A tool could not do what was asked; the message is shown to the LLM."""


class AccessDenied(ToolError):
    """The path is outside the repository, inside .git, or a secret file."""


def _is_denied(rel: str) -> bool:
    parts = rel.lower().split("/")  # case-insensitive: .ENV is .env on Windows and macOS
    name = parts[-1]
    if ".git" in parts:
        return True
    return name != ".env.example" and bool(_SECRET_NAME.match(name))


def wrap_untrusted(label: str, text: str) -> str:
    """Code from the PR is data, never instructions (spec 4.6); its closing tag is neutralised."""
    safe_label = label.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")
    body = _CLOSE_TAG.sub(r"<\\/untrusted-code", text)
    return f'<untrusted-code source="{safe_label}">\n{body}\n</untrusted-code>'


class RepoFS:
    def __init__(self, root: Path, secret_lines: dict[str, set[int]] | None = None) -> None:
        self.root = Path(root).resolve()
        self.secret_lines = secret_lines or {}
        self._files: list[str] | None = None

    def files(self) -> list[str]:
        """Tracked plus new (not ignored) files, as repo-relative POSIX paths."""
        if self._files is None:
            try:
                out = subprocess.run(
                    ["git", "-C", str(self.root), "-c", "core.quotePath=false", "ls-files", "-z",
                     "--cached", "--others", "--exclude-standard"],
                    check=True, capture_output=True,
                ).stdout
                names = [n for n in out.decode("utf-8", errors="replace").split("\0") if n]
            except (OSError, subprocess.CalledProcessError):
                names = self._walk()
            self._files = sorted({n for n in names if not _is_denied(n)})
        return self._files

    def _walk(self) -> list[str]:
        names = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            rel_dir = Path(dirpath).relative_to(self.root).as_posix()
            names += [f if rel_dir == "." else f"{rel_dir}/{f}" for f in filenames]
        return names

    def relative(self, path: str) -> str:
        raw = (path or "").replace("\\", "/").strip()
        if not raw or raw.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", raw):
            raise AccessDenied(f"chỉ được dùng đường dẫn tương đối trong repo: {path!r}")
        parts = [p for p in PurePosixPath(raw).parts if p != "."]
        if not parts or ".." in parts:
            raise AccessDenied(f"đường dẫn ra ngoài repo: {path!r}")
        rel = "/".join(parts)
        if _is_denied(rel):
            raise AccessDenied(rel)
        return rel

    def resolve(self, path: str) -> Path:
        rel = self.relative(path)
        full = (self.root / rel).resolve()
        if not full.is_relative_to(self.root):
            raise AccessDenied(f"liên kết trỏ ra ngoài repo: {rel}")
        # A committed symlink (docs/notes.md -> ../app/.env) must not unlock a denied target.
        if full != self.root and _is_denied(full.relative_to(self.root).as_posix()):
            raise AccessDenied(f"{rel} trỏ tới file bị cấm")
        return full

    def lines(self, path: str) -> list[str]:
        rel = self.relative(path)
        full = self.resolve(rel)
        if not full.is_file():
            raise ToolError(f"không có file {rel}")
        if full.stat().st_size > MAX_BYTES:
            raise ToolError(f"file quá lớn (> 1 MB): {rel}")
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
        real = full.relative_to(self.root).as_posix()
        masked = self.secret_lines.get(rel, set()) | self.secret_lines.get(real, set())
        return [mask_line() if i in masked else line for i, line in enumerate(lines, start=1)]

    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> str:
        rel = self.relative(path)
        lines = self.lines(rel)
        if not lines:
            return wrap_untrusted(rel, "(file rỗng)")
        if start_line > len(lines):
            raise ToolError(f"{rel} chỉ có {len(lines)} dòng")
        start = max(1, start_line)
        last = start + MAX_LINES - 1
        end = min(len(lines), last, end_line if end_line is not None else last)
        if end < start:
            raise ToolError("end_line phải lớn hơn hoặc bằng start_line")
        body = "\n".join(f"{n:>5}| {lines[n - 1]}" for n in range(start, end + 1))
        return wrap_untrusted(f"{rel}:{start}-{end}", redact(body))

    def list_files(self, glob: str = "*", limit: int = 300) -> str:
        matches = [f for f in self.files() if fnmatch(f, glob)]
        shown = matches[:limit]
        note = f"\n… ({len(matches)} file, hãy dùng glob hẹp hơn)" if len(matches) > limit else ""
        if not matches:
            return "(không có file nào khớp)"
        return wrap_untrusted(f"files {glob}", "\n".join(shown)) + note
