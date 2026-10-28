"""
self_destruct.py
-----------------
Two independent "self-destruct" mechanisms for the vault:

1. record_failed_attempt() / reset_failed_attempts() - tracks consecutive
   wrong master-password attempts in a small plaintext sidecar file next
   to the vault (the vault file itself is encrypted, so a wrong guess
   can't update anything inside it - hence the separate counter file).
   After MAX_FAILED_ATTEMPTS in a row, the vault is permanently wiped.

2. panic_wipe() - an explicit, user-triggered irreversible wipe, for
   when you deliberately want the vault gone right now.

Both end up calling secure_delete(), which overwrites a file's bytes
before unlinking it. That's a best-effort measure, not a guarantee
against forensic recovery (SSD wear-leveling in particular can leave
remnants no software overwrite can reach) - but it's meaningfully
better than a plain delete.
"""

import os
import json

MAX_FAILED_ATTEMPTS = 10


def _meta_path(vault_path: str) -> str:
    return vault_path + ".meta"


def _read_meta(vault_path: str) -> dict:
    try:
        with open(_meta_path(vault_path), "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _write_meta(vault_path: str, data: dict) -> None:
    try:
        with open(_meta_path(vault_path), "w") as f:
            json.dump(data, f)
    except OSError:
        pass


def failed_attempt_count(vault_path: str) -> int:
    return int(_read_meta(vault_path).get("failed_attempts", 0))


def reset_failed_attempts(vault_path: str) -> None:
    _write_meta(vault_path, {"failed_attempts": 0})


def record_failed_attempt(vault_path: str) -> int | None:
    """Increments the failed-attempt counter. Returns the new count, or
    None if the threshold was just reached and the vault has now been
    permanently wiped."""
    count = failed_attempt_count(vault_path) + 1
    if count >= MAX_FAILED_ATTEMPTS:
        secure_delete(vault_path)
        secure_delete(_meta_path(vault_path))
        return None
    _write_meta(vault_path, {"failed_attempts": count})
    return count


def secure_delete(path: str) -> bool:
    """Overwrites a file with random bytes before deleting it. Best
    effort: if the overwrite fails for any reason, still tries a plain
    delete rather than leaving the file in place."""
    if not os.path.isfile(path):
        return False
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        os.remove(path)
        return True
    except OSError:
        return False


def panic_wipe(vault_path: str) -> bool:
    """Immediately and permanently destroys the vault file and its
    metadata sidecar. Irreversible - there is no backup, no recovery."""
    ok = secure_delete(vault_path)
    secure_delete(_meta_path(vault_path))
    return ok
