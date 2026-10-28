"""
breach_check.py
---------------
Checks a password against the "Have I Been Pwned" Pwned Passwords API
using k-anonymity: only the first 5 characters of the password's SHA-1
hash are ever sent over the network. HIBP returns every hash suffix
that shares that prefix (thousands of them), and we check locally
whether our full hash appears - the real password, and even its full
hash, never leaves the machine.

Reference: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

import hashlib
import urllib.request
import urllib.error

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
TIMEOUT_SECONDS = 8


class BreachCheckError(Exception):
    """Raised when the check couldn't be completed (no network, API down, etc.)."""
    pass


def check_password_breach(password: str) -> int:
    """Returns the number of times this password has appeared in known
    breaches (0 = not found). Raises BreachCheckError if the check
    itself failed (e.g. offline) - that is NOT the same as 0 results."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    req = urllib.request.Request(
        API_URL.format(prefix=prefix),
        headers={"User-Agent": "Vault-local-password-manager", "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        raise BreachCheckError(f"Couldn't reach the breach-check service: {e}") from e
    except Exception as e:
        raise BreachCheckError(f"Breach check failed: {e}") from e

    for line in body.splitlines():
        if ":" not in line:
            continue
        hash_suffix, count_str = line.split(":", 1)
        if hash_suffix.strip() == suffix:
            return int(count_str.strip())
    return 0
