"""Password strength checker.

Scores a password using estimated entropy, character variety and a
check against a list of common passwords. Nothing is stored or sent
anywhere: everything runs locally.
"""

import argparse
import getpass
import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

COMMON_PASSWORDS_FILE = Path(__file__).with_name("common_passwords.txt")


def load_common_passwords(path: Path = COMMON_PASSWORDS_FILE) -> set[str]:
    if not path.exists():
        return set()
    with path.open(encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}


def charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 33
    return size


def entropy_bits(password: str) -> float:
    pool = charset_size(password)
    if not password or pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def has_sequence(password: str, length: int = 3) -> bool:
    """True if the password contains runs like 'abc', '123' or 'cba'."""
    p = password.lower()
    for i in range(len(p) - length + 1):
        chunk = p[i : i + length]
        diffs = {ord(chunk[j + 1]) - ord(chunk[j]) for j in range(length - 1)}
        if diffs in ({1}, {-1}) and chunk.isalnum():
            return True
    return False


def has_repeats(password: str, length: int = 3) -> bool:
    return re.search(r"(.)\1{%d,}" % (length - 1), password) is not None


@dataclass
class Result:
    score: int  # 0 (very weak) .. 4 (very strong)
    label: str
    entropy: float
    feedback: list[str] = field(default_factory=list)


LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]


def check_password(password: str, common: set[str] | None = None) -> Result:
    common = load_common_passwords() if common is None else common
    feedback: list[str] = []
    bits = entropy_bits(password)

    if password.lower() in common:
        return Result(0, LABELS[0], bits, ["This is a commonly used password. Pick something unique."])

    if len(password) < 8:
        feedback.append("Use at least 8 characters (12+ is better).")
    if not re.search(r"[a-z]", password):
        feedback.append("Add lowercase letters.")
    if not re.search(r"[A-Z]", password):
        feedback.append("Add uppercase letters.")
    if not re.search(r"[0-9]", password):
        feedback.append("Add numbers.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        feedback.append("Add symbols such as ! @ # $.")
    if has_sequence(password):
        feedback.append("Avoid sequences like 'abc' or '123'.")
        bits -= 10
    if has_repeats(password):
        feedback.append("Avoid repeated characters like 'aaa'.")
        bits -= 10

    bits = max(bits, 0.0)
    if bits < 28:
        score = 0
    elif bits < 36:
        score = 1
    elif bits < 60:
        score = 2
    elif bits < 80:
        score = 3
    else:
        score = 4

    if len(password) < 8:
        score = min(score, 1)

    if not feedback:
        feedback.append("Looks good.")
    return Result(score, LABELS[score], round(bits, 1), feedback)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check how strong a password is.")
    parser.add_argument("password", nargs="?", help="password to check (omit to type it hidden)")
    args = parser.parse_args(argv)

    password = args.password or getpass.getpass("Password: ")
    result = check_password(password)

    bar = "█" * (result.score + 1) + "░" * (4 - result.score)
    print(f"\nStrength : {result.label}  [{bar}]")
    print(f"Entropy  : {result.entropy} bits")
    print("Tips     :")
    for tip in result.feedback:
        print(f"  - {tip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
