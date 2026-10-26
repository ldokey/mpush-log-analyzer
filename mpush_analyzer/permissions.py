"""Best-effort private file modes on supported operating systems.

POSIX: enforce restrictive 0600/0700 permissions. Windows: never call os.fchmod,
which is not available; effective security is governed by inherited NTFS ACLs.
Use a user-private local folder for customer logs, not a shared NAS path.
"""
from __future__ import annotations
import os
from pathlib import Path


def private_fd(fd: int) -> None:
    if os.name != "nt" and hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)


def private_path(path: str | Path, *, directory: bool = False) -> None:
    if os.name != "nt":
        os.chmod(path, 0o700 if directory else 0o600)
