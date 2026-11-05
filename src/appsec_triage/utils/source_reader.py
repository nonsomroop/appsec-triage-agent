import fnmatch
import os
import stat
from pathlib import Path

from appsec_triage.scanners.base import validate_target

SECRET_PATTERNS = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks",
    "id_rsa*", "id_ed25519*", "id_dsa*", "id_ecdsa*", "credentials*",
    "secrets*", ".netrc", ".npmrc", ".pypirc", "*.keystore",
)
SECRET_DIRECTORIES = {".git", ".ssh", ".aws", ".azure", ".gnupg", ".kube"}


def excluded_path(path: Path) -> bool:
    return any(
        part.lower() in SECRET_DIRECTORIES
        or any(fnmatch.fnmatch(part.lower(), pattern) for pattern in SECRET_PATTERNS)
        for part in path.parts
    )


class SourceReadError(ValueError):
    pass


class SourceReader:
    def __init__(self, root: str | Path, *, max_file_bytes: int = 1_000_000,
                 max_context_chars: int = 12_000, context_lines: int = 20):
        self.root = validate_target(root)
        if min(max_file_bytes, max_context_chars) < 1 or context_lines < 0:
            raise ValueError("Invalid source limits")
        self.max_file_bytes = max_file_bytes
        self.max_context_chars = max_context_chars
        self.context_lines = context_lines

    def read(self, file_path: str, start_line: int, end_line: int) -> str:
        if start_line < 1 or end_line < start_line:
            raise SourceReadError("Invalid source range")
        supplied = Path(file_path)
        if ".." in supplied.parts or ":" in file_path or "\\" in file_path:
            raise SourceReadError("Unsafe source path")
        candidate = self.root / supplied
        try:
            relative = candidate.relative_to(self.root)
            if excluded_path(relative):
                raise SourceReadError("Source path is excluded")
            # Reject all symlinks/junctions, including aliases to secret files.
            current = self.root
            for part in relative.parts:
                current = current / part
                if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
                    raise SourceReadError("Source links are not permitted")
            resolved = candidate.resolve(strict=True)
            resolved_relative = resolved.relative_to(self.root)
            if excluded_path(resolved_relative):
                raise SourceReadError("Resolved source path is excluded")
            before = resolved.stat()
            if not stat.S_ISREG(before.st_mode) or before.st_size > self.max_file_bytes:
                raise SourceReadError("Source is not a regular file within size limits")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            with os.fdopen(os.open(resolved, flags), "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not os.path.samestat(before, opened):
                    raise SourceReadError("Source changed during read")
                data = stream.read(self.max_file_bytes + 1)
            if len(data) > self.max_file_bytes:
                raise SourceReadError("Source exceeds size limit")
            lines = data.decode("utf-8", errors="replace").splitlines()
            if end_line > len(lines):
                raise SourceReadError("Finding is outside source range")
            first = max(1, start_line - self.context_lines)
            last = min(len(lines), end_line + self.context_lines)
            context = "\n".join(f"{i}: {lines[i - 1]}" for i in range(first, last + 1))
            if len(context) > self.max_context_chars:
                context = context[:self.max_context_chars] + "\n[context truncated]"
            return context
        except (OSError, ValueError) as exc:
            if isinstance(exc, SourceReadError):
                raise
            raise SourceReadError("Source is unavailable or outside authorised root") from None
