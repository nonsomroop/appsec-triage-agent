"""Bounded file inventory for comparing scanner output with the selected folder."""
import os
import time
from pathlib import Path

from appsec_triage.models.scan import Coverage


def inventory(root: Path, coverage: Coverage) -> None:
    coverage.inventory_files = []
    coverage.inventory_complete = True
    deadline = time.monotonic() + 5

    def unreadable(error):
        coverage.inventory_complete = False

    # Git internals are outside the working-file inventory. Do not follow links.
    for directory, folders, files in os.walk(root, onerror=unreadable, followlinks=False):
        parent = Path(directory)
        for folder in folders[:]:
            path = parent / folder
            if folder == ".git":
                folders.remove(folder)
            elif path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                folders.remove(folder)
                coverage.inventory_complete = False
        for name in files:
            if name == ".git":
                continue
            coverage.inventory_files.append((parent / name).relative_to(root).as_posix())
            if len(coverage.inventory_files) >= 100_000 or time.monotonic() >= deadline:
                coverage.inventory_complete = False
                return
        if time.monotonic() >= deadline:
            coverage.inventory_complete = False
            return
    coverage.inventory_files.sort()
