"""
vault.py
--------
In-memory vault model + persistence glue. This is what the UI talks to.

Entry schema (dict):
{
  "id": "<uuid4>",
  "kind": "login" | "wifi",   # "login" for regular site/app credentials,
                              # "wifi" for a saved Wi-Fi network
  "title": "...",             # site/app name, or the Wi-Fi SSID
  "username": "...",          # unused for "wifi" entries
  "password": "...",
  "url": "...",
  "security_type": "...",     # e.g. "WPA2" - only meaningful for "wifi"
  "notes": "...",
  "tags": ["work", "banking"],   # free-form, lowercase, user-defined
  "favorite": False,
  "updated_at": "<iso8601>"
}
"""

import uuid
from datetime import datetime, timezone

import vault_crypto


class Vault:
    def __init__(self, path: str):
        self.path = path
        self.master_password: str | None = None
        self.salt: bytes | None = None
        self.entries: list[dict] = []
        self.unlocked = False

    # ---------- lifecycle ----------

    def exists(self) -> bool:
        return vault_crypto.vault_exists(self.path)

    def create_new(self, master_password: str) -> None:
        """Create a brand-new empty vault protected by master_password."""
        self.entries = []
        vault_crypto.save_vault(self.path, master_password, {"entries": self.entries})
        # re-derive salt by loading once so subsequent saves reuse it
        _, salt = vault_crypto.load_vault(self.path, master_password)
        self.salt = salt
        self.master_password = master_password
        self.unlocked = True

    def unlock(self, master_password: str) -> None:
        """Raises vault_crypto.VaultError if the password is wrong."""
        data, salt = vault_crypto.load_vault(self.path, master_password)
        self.entries = data.get("entries", [])
        self.salt = salt
        self.master_password = master_password
        self.unlocked = True

    def lock(self) -> None:
        """Wipe decrypted material from memory."""
        self.entries = []
        self.master_password = None
        self.salt = None
        self.unlocked = False

    def _persist(self) -> None:
        if not self.unlocked:
            raise RuntimeError("Vault is locked; cannot save.")
        vault_crypto.save_vault_existing_salt(
            self.path, self.master_password, self.salt, {"entries": self.entries}
        )

    # ---------- entry CRUD ----------

    def add_entry(self, title: str, username: str, password: str, url: str = "", notes: str = "",
                  tags: list[str] | None = None, favorite: bool = False, kind: str = "login",
                  security_type: str = "") -> dict:
        entry = {
            "id": str(uuid.uuid4()),
            "kind": kind,
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "security_type": security_type,
            "notes": notes,
            "tags": sorted(set(t.strip().lower() for t in (tags or []) if t.strip())),
            "favorite": bool(favorite),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self.entries.append(entry)
        self._persist()
        return entry

    def toggle_favorite(self, entry_id: str) -> None:
        for e in self.entries:
            if e["id"] == entry_id:
                e["favorite"] = not e.get("favorite", False)
                self._persist()
                return
        raise KeyError(f"No entry with id {entry_id}")

    def duplicate_password_ids(self) -> set:
        """Entry ids whose password is reused by at least one other entry."""
        by_password: dict[str, list[str]] = {}
        for e in self.entries:
            by_password.setdefault(e["password"], []).append(e["id"])
        dupes = set()
        for ids in by_password.values():
            if len(ids) > 1:
                dupes.update(ids)
        return dupes

    def wifi_entries(self) -> list[dict]:
        return [e for e in self.entries if e.get("kind") == "wifi"]

    def all_tags(self) -> list[str]:
        tags = set()
        for e in self.entries:
            tags.update(e.get("tags", []))
        return sorted(tags)

    def update_entry(self, entry_id: str, **fields) -> None:
        if "tags" in fields:
            fields["tags"] = sorted(set(t.strip().lower() for t in (fields["tags"] or []) if t.strip()))
        for e in self.entries:
            if e["id"] == entry_id:
                e.update(fields)
                e["updated_at"] = datetime.now(timezone.utc).isoformat()
                self._persist()
                return
        raise KeyError(f"No entry with id {entry_id}")

    def delete_entry(self, entry_id: str) -> None:
        self.entries = [e for e in self.entries if e["id"] != entry_id]
        self._persist()

    def change_master_password(self, new_password: str) -> None:
        """Re-encrypt the whole vault under a new master password + new salt."""
        vault_crypto.save_vault(self.path, new_password, {"entries": self.entries})
        _, salt = vault_crypto.load_vault(self.path, new_password)
        self.salt = salt
        self.master_password = new_password

    def search(self, query: str, tag: str | None = None, favorites_only: bool = False,
               kind: str | None = None) -> list[dict]:
        results = list(self.entries)
        if favorites_only:
            results = [e for e in results if e.get("favorite", False)]
        if kind:
            results = [e for e in results if e.get("kind", "login") == kind]
        if tag:
            results = [e for e in results if tag in e.get("tags", [])]

        q = query.lower().strip()
        if not q:
            return results
        return [
            e for e in results
            if q in e["title"].lower() or q in e.get("username", "").lower()
            or q in e.get("url", "").lower() or any(q in t for t in e.get("tags", []))
        ]
