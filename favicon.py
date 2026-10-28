"""
favicon.py
----------
Fetches and locally caches a site's favicon so entries can show a real
icon instead of plain initials, the way Apple's Passwords app does.

Design:
- Uses Google's public favicon service (no API key, no auth) - it does
  the messy work of finding/resizing a site's actual favicon for us.
- Every icon is cached to disk by domain, so repeat launches don't hit
  the network at all once warmed up.
- This module does ONLY network + file I/O, no Tkinter - the UI layer
  calls fetch_favicon_path() from a background thread (network calls
  must never block the UI thread) and then loads the cached file into
  a tk.PhotoImage on the main thread, since Tk widgets aren't
  thread-safe. Tk can decode PNG natively (8.6+), so no Pillow needed
  here even though it's available elsewhere in the app.
"""

import os
import re
import urllib.request
import urllib.error
import urllib.parse

FAVICON_SERVICE = "https://www.google.com/s2/favicons?domain={domain}&sz=64"
TIMEOUT_SECONDS = 5

CACHE_DIR = os.path.expanduser("~/.local/share/password_manager/favicon_cache")


def extract_domain(url_or_title: str) -> str | None:
    """Pulls a bare domain out of a URL (or returns None if it doesn't
    look like one). Tolerant of missing scheme: 'gmail.com' or
    'https://mail.google.com/mail' both work."""
    if not url_or_title:
        return None
    text = url_or_title.strip()
    if "://" not in text:
        text = "https://" + text
    try:
        host = urllib.parse.urlparse(text).netloc
    except ValueError:
        return None
    host = host.split("@")[-1]  # strip any userinfo
    host = host.split(":")[0]   # strip port
    if not host or "." not in host:
        return None
    if not re.match(r"^[a-zA-Z0-9.-]+$", host):
        return None
    return host.lower()


def _cache_path(domain: str) -> str:
    safe_name = re.sub(r"[^a-z0-9.-]", "_", domain.lower())
    return os.path.join(CACHE_DIR, f"{safe_name}.png")


def fetch_favicon_path(url_or_domain: str) -> str | None:
    """Returns a local file path to this site's cached favicon PNG,
    fetching and caching it first if needed. Returns None if there's
    no usable domain or the fetch failed (offline, blocked, etc.) -
    callers should fall back to an initials avatar in that case."""
    domain = extract_domain(url_or_domain)
    if not domain:
        return None

    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_file = _cache_path(domain)
    if os.path.isfile(cache_file) and os.path.getsize(cache_file) > 0:
        return cache_file

    req = urllib.request.Request(
        FAVICON_SERVICE.format(domain=urllib.parse.quote(domain)),
        headers={"User-Agent": "Vault-local-password-manager"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            data = resp.read()
    except (urllib.error.URLError, TimeoutError, OSError):
        return None

    if not data:
        return None

    try:
        with open(cache_file, "wb") as f:
            f.write(data)
    except OSError:
        return None

    return cache_file
