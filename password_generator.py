"""
password_generator.py
----------------------
Cryptographically secure random password generation.
Uses `secrets` (not `random`) - `random` is NOT safe for security purposes.
"""

import secrets
import string

AMBIGUOUS = "lI1O0"


def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = True,
) -> str:
    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?/")

    if not pools:
        raise ValueError("At least one character set must be enabled.")

    full_alphabet = "".join(pools)
    if avoid_ambiguous:
        full_alphabet = "".join(c for c in full_alphabet if c not in AMBIGUOUS)
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]

    if length < len(pools):
        length = len(pools)

    # Guarantee at least one char from each selected pool, rest random.
    password_chars = [secrets.choice(p) for p in pools if p]
    remaining = length - len(password_chars)
    password_chars += [secrets.choice(full_alphabet) for _ in range(remaining)]

    # Shuffle securely (Fisher-Yates using secrets)
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


WORDLIST = [
    "lantern", "compost", "drizzle", "vinyl", "ember", "canyon", "thicket",
    "marble", "satin", "copper", "willow", "quartz", "harbor", "meadow",
    "falcon", "cinder", "granite", "velvet", "orchid", "basalt", "cobalt",
    "driftwood", "prairie", "sparrow", "tundra", "amber", "cascade", "pebble",
    "juniper", "maple", "ridge", "lagoon", "thistle", "ember", "sable",
]


def generate_passphrase(num_words: int = 4, separator: str = "-", add_number: bool = True) -> str:
    words = [secrets.choice(WORDLIST).capitalize() for _ in range(num_words)]
    if add_number:
        words.append(str(secrets.randbelow(90) + 10))
    return separator.join(words)
