"""
strength.py
-----------
A lightweight, dependency-free password strength estimator.

This is NOT a full zxcvbn-style pattern cracker - it's a practical
heuristic: effective character-space entropy, with penalties for
common weak patterns (repeats, sequences, dictionary words, keyboard
walks). Good enough to steer someone away from genuinely bad
passwords without pulling in a large dependency.

Returns a score 0-4 and a short label, matching the scale most
password managers show:
  0 = Very weak   1 = Weak   2 = Fair   3 = Strong   4 = Very strong
"""

import math
import re
import string

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "letmein",
    "monkey", "111111", "iloveyou", "admin", "welcome", "login",
    "princess", "qwerty123", "solo", "passw0rd", "starwars", "dragon",
    "football", "baseball", "superman", "trustno1", "freedom", "whatever",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def _char_space(password: str) -> int:
    space = 0
    if re.search(r"[a-z]", password):
        space += 26
    if re.search(r"[A-Z]", password):
        space += 26
    if re.search(r"[0-9]", password):
        space += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        space += 32
    return max(space, 1)


def _has_sequence(password: str, length: int = 4) -> bool:
    lower = password.lower()
    # Ascending/descending alphabetic or numeric runs, e.g. "abcd", "4321"
    for i in range(len(lower) - length + 1):
        chunk = lower[i:i + length]
        codes = [ord(c) for c in chunk]
        if all(codes[j + 1] - codes[j] == 1 for j in range(len(codes) - 1)):
            return True
        if all(codes[j] - codes[j + 1] == 1 for j in range(len(codes) - 1)):
            return True
    return False


def _has_keyboard_walk(password: str, length: int = 4) -> bool:
    lower = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - length + 1):
            if row[i:i + length] in lower:
                return True
    return False


def _has_repeats(password: str, run: int = 3) -> bool:
    return bool(re.search(r"(.)\1{" + str(run - 1) + ",}", password))


def estimate_strength(password: str) -> tuple[int, str]:
    """Returns (score 0-4, label)."""
    if not password:
        return 0, "Empty"

    length = len(password)
    space = _char_space(password)
    bits = length * math.log2(space)

    penalty = 0
    lower_pw = password.lower()
    if lower_pw in COMMON_PASSWORDS or lower_pw.strip(string.digits) in COMMON_PASSWORDS:
        penalty += 30
    if _has_sequence(password):
        penalty += 12
    if _has_keyboard_walk(password):
        penalty += 12
    if _has_repeats(password):
        penalty += 10
    if length < 8:
        penalty += 15

    effective_bits = max(bits - penalty, 0)

    if effective_bits < 28:
        return 0, "Very weak"
    elif effective_bits < 36:
        return 1, "Weak"
    elif effective_bits < 60:
        return 2, "Fair"
    elif effective_bits < 80:
        return 3, "Strong"
    else:
        return 4, "Very strong"
