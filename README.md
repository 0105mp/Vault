# Vault — a local encrypted password manager

A desktop password manager that runs entirely on your machine. Nothing is
ever sent over the network. The vault file is useless without your master
password.

## Run it

```bash
pip install -r requirements.txt
python3 app.py
```

First run creates a new vault at `~/.local/share/password_manager/vault.json`
(or pass `--vault /path/to/file.json` to use a different location — e.g. a
synced folder).

## How it works

- **Master password → key**: PBKDF2-HMAC-SHA256, 600,000 iterations, random
  16-byte salt per vault. The master password itself is never written to
  disk, ever — only used in memory to derive the encryption key.
- **Encryption**: AES-256-GCM (authenticated — the vault file can't be
  silently tampered with; any corruption or wrong key fails loudly instead
  of returning garbage).
- **Storage**: one JSON file holding `salt`, `nonce`, and `ciphertext`
  (all base64). The plaintext entries only ever exist in memory while the
  vault is unlocked.
- **Auto-lock**: vault locks itself after 3 minutes of no keyboard/mouse
  activity (`IDLE_LOCK_MS` in `app.py`).
- **Clipboard**: copying a password clears the clipboard automatically
  after 20 seconds (`CLIPBOARD_CLEAR_MS` in `app.py`).
- **Strength meter**: a dependency-free heuristic (length + character
  variety + penalties for common/sequential/repeated patterns) shown live
  while typing or generating a password.
- **Breach check**: checks a password against HaveIBeenPwned's Pwned
  Passwords database using k-anonymity — only the first 5 characters of
  its SHA-1 hash are ever sent; the real password never leaves your machine.
- **Tags**: free-form tags per entry, with filter chips above the list.

## Files

| File                   | Purpose                                         |
|-------------------------|--------------------------------------------------|
| `vault_crypto.py`       | Key derivation, AES-GCM encrypt/decrypt, file I/O |
| `vault.py`              | In-memory vault model, entry CRUD, tags           |
| `password_generator.py` | Cryptographically secure password/passphrase generation (`secrets`, not `random`) |
| `strength.py`           | Dependency-free password strength heuristic       |
| `breach_check.py`       | HaveIBeenPwned k-anonymity breach lookup          |
| `theme.py`              | Colors, fonts, icon generation                    |
| `app.py`                | Tkinter UI                                       |

## Honest limitations (read this)

This is a solid, correctly-built personal tool — but it hasn't been through
third-party security audits the way Bitwarden, 1Password, or KeePass have.
For anything where a compromise would be catastrophic (primary email,
banking, your Amazon account after a hack), I'd still lean on one of those.
Good uses for this one:
- Learning project / portfolio piece demonstrating applied crypto
- Lower-stakes accounts (forums, newsletters, trial accounts)
- A "how would I build this" exercise before trusting it with everything

If you outgrow it, the data format is simple JSON — easy to write an
export script later.

## No recovery

There is no password reset. If you forget the master password, the vault
cannot be decrypted by anyone, including you. That's the whole point of
the design — but it means you need a safe way to remember or store that
one password (e.g. memorize it, or write it on paper somewhere secure —
never in a plaintext file).

## Ideas for extending it further

- Export/import (encrypted) backups
- Cross-device sync via your own encrypted file in Drive/Dropbox (the
  vault file is already self-contained and portable)
- TOTP/2FA code storage alongside entries
- Duplicate/reused-password detection across the whole vault
