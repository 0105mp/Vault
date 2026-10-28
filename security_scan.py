"""
security_scan.py
-----------------
Vault-wide security analysis, powering the "Security" sidebar view
(similar to Apple Passwords' Security Recommendations). Pure logic,
no Tkinter - the UI renders whatever this returns.
"""

from vault import Vault
from strength import estimate_strength
from breach_check import check_password_breach, BreachCheckError

WEAK_SCORE_THRESHOLD = 1  # entries scoring <= this (Very weak / Weak) are flagged


def weak_entries(vault: Vault) -> list[dict]:
    flagged = []
    for e in vault.entries:
        score, label = estimate_strength(e["password"])
        if score <= WEAK_SCORE_THRESHOLD:
            flagged.append({**e, "_strength_label": label, "_strength_score": score})
    return flagged


def reused_entries(vault: Vault) -> list[dict]:
    dupe_ids = vault.duplicate_password_ids()
    return [e for e in vault.entries if e["id"] in dupe_ids]


def breach_scan(vault: Vault, cache: dict | None = None) -> dict:
    """Checks every entry's password against HaveIBeenPwned and returns
    {entry_id: breach_count} for the ones found in a known breach.
    Makes network calls - callers must run this on a background thread,
    never the UI thread. `cache` is an optional {password: count|None}
    dict that the caller can keep across scans so a password reused by
    several entries, or re-scanned later, only hits the network once."""
    cache = cache if cache is not None else {}
    results = {}
    for e in vault.entries:
        pw = e["password"]
        if pw not in cache:
            try:
                cache[pw] = check_password_breach(pw)
            except BreachCheckError:
                cache[pw] = None
        count = cache[pw]
        if count:
            results[e["id"]] = count
    return results


def summarize(vault: Vault) -> dict:
    """Quick counts for sidebar badges - cheap, no network calls."""
    return {
        "weak": len(weak_entries(vault)),
        "reused": len(reused_entries(vault)),
        "total_issues_no_breach": len(
            {e["id"] for e in weak_entries(vault)} | {e["id"] for e in reused_entries(vault)}
        ),
    }
