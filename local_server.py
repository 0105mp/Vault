"""
local_server.py
----------------
A tiny localhost-only HTTP server that lets the companion browser
extension ("Vault Quick Copy") list entry titles/usernames and fetch a
single password on demand, without the extension ever holding the whole
vault. It only runs while the desktop app has the vault unlocked, and a
pairing token (generated once, stored on disk, shown to you in the app
so you can paste it into the extension's options page) is required on
every request.

Security notes (this is a portfolio/personal project, not a hardened
product):
 - Binds to 127.0.0.1 only - never reachable from the network.
 - Every request must carry the X-Vault-Token header matching the token
   on disk; a wrong or missing token gets a 401 and nothing else.
 - The entries listing never includes passwords; only a POST to
   /entries/<id>/password (still requires the token) returns the
   password for exactly one entry, fetched the moment you click it.
 - Wi-Fi entries are excluded - they're not relevant to a web login
   helper.
 - If the port is already taken (e.g. a second instance of the app),
   start() just fails quietly and the extension's popup will show
   "can't reach Vault" - it never crashes the app.
"""

import os
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8743
TOKEN_PATH = os.path.expanduser("~/.local/share/password_manager/extension_token.txt")


def get_or_create_token() -> str:
    os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)
    if os.path.isfile(TOKEN_PATH):
        try:
            token = open(TOKEN_PATH).read().strip()
            if token:
                return token
        except OSError:
            pass
    token = secrets.token_urlsafe(32)
    try:
        with open(TOKEN_PATH, "w") as f:
            f.write(token)
        os.chmod(TOKEN_PATH, 0o600)
    except OSError:
        pass
    return token


class VaultServer:
    """Owns the HTTP server lifecycle. app.py creates one instance and
    calls start()/stop() as the vault unlocks/locks."""

    def __init__(self, vault):
        self.vault = vault
        self.token = get_or_create_token()
        self._httpd = None
        self._thread = None

    @property
    def running(self) -> bool:
        return self._httpd is not None

    def start(self):
        if self._httpd is not None:
            return
        token = self.token
        vault = self.vault

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass  # keep stdout clean - the terminal is the user's build log, not ours

            def _authed(self):
                return self.headers.get("X-Vault-Token") == token

            def _send_json(self, status, payload):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Headers", "X-Vault-Token, Content-Type")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_OPTIONS(self):
                self._send_json(200, {})

            def do_GET(self):
                if self.path == "/ping":
                    self._send_json(200, {"ok": True})
                    return
                if self.path == "/entries":
                    if not self._authed():
                        self._send_json(401, {"error": "bad token"})
                        return
                    if not vault.unlocked:
                        self._send_json(423, {"error": "vault locked"})
                        return
                    items = [
                        {"id": e["id"], "title": e["title"], "username": e.get("username", ""),
                         "url": e.get("url", "")}
                        for e in vault.entries if e.get("kind", "login") != "wifi"
                    ]
                    self._send_json(200, {"entries": items})
                    return
                self._send_json(404, {"error": "not found"})

            def do_POST(self):
                if not self._authed():
                    self._send_json(401, {"error": "bad token"})
                    return
                if not vault.unlocked:
                    self._send_json(423, {"error": "vault locked"})
                    return
                parts = self.path.strip("/").split("/")
                if len(parts) == 3 and parts[0] == "entries" and parts[2] == "password":
                    entry_id = parts[1]
                    entry = next((e for e in vault.entries if e["id"] == entry_id), None)
                    if not entry:
                        self._send_json(404, {"error": "no such entry"})
                        return
                    self._send_json(200, {"password": entry["password"]})
                    return
                self._send_json(404, {"error": "not found"})

        try:
            self._httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
        except OSError:
            self._httpd = None
            return
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._httpd is None:
            return
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
        except Exception:
            pass
        self._httpd = None
        self._thread = None
