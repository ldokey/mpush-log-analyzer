"""Best-effort local filesystem permissions across POSIX and Windows.

POSIX files are chmod 0600. Windows ACLs must be enforced by the
underlying NTFS/share permissions; chmod does not replace an ACL audit.
"""
from __future__ import annotations
import os

def private_file_mode(fd: int, mode: int = 0o600) -> None:
    if os.name != "nt":
        os.fchmod(fd, mode)
