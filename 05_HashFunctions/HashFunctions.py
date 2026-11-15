"""
Hash Functions: Great for Files, Bad for Passwords
==================================================
Experiments:
  [1] Integrity : SHA-256 as a data fingerprint (deterministic,
                  fixed-length output, and the avalanche effect).
  [2] Passwords : the same properties end up leaking passwords
                  (plain SHA-256, SHA-256 + salt, and bcrypt).

Requirements: pip install bcrypt
"""

import hashlib
import os
import random
import statistics
import string
import time

import bcrypt

# Number of trials used to measure the avalanche effect
NUM_TRIALS = 1000
# bcrypt cost: every +1 doubles the hashing time
BCRYPT_COST = 12
# Size of a leaked wordlist commonly used by attackers
WORDLIST_SIZE = 14_000_000


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def percent_bits_changed(a: bytes, b: bytes) -> float:
    # Compare two digests bit by bit, result in percent
    diff = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
    return diff / (len(a) * 8) * 100


def change_one_char(text: str) -> str:
    # Replace exactly one character with a different character
    pos = random.randrange(len(text))
    choices = string.ascii_letters + string.digits
    new_char = random.choice(choices.replace(text[pos], ""))
    return text[:pos] + new_char + text[pos + 1:]


def guesses_per_second(hash_func, words: list) -> float:
    # How many password guesses can be tried per second
    start = time.perf_counter()
    for word in words:
        hash_func(word.encode())
    return len(words) / (time.perf_counter() - start)


# ==========================================================
# [1] HASHING FOR INTEGRITY: a data fingerprint
# ==========================================================
def integrity_demo() -> None:
    print("=== [1] SHA-256 as a data fingerprint ===")
    original = b"Transfer Rp1,000,000 to account 7710-2231"
    modified = b"Transfer Rp9,000,000 to account 7710-2231"
    # Simulate a 5 MB file
    large_file = os.urandom(5 * 1024 * 1024)

    h_original = hashlib.sha256(original).digest()
    h_modified = hashlib.sha256(modified).digest()
    print(f"Original     : {h_original.hex()}")
    print(f"Modified     : {h_modified.hex()}")
    print(f"Bits changed : "
          f"{percent_bits_changed(h_original, h_modified):.1f}% "
          f"(only 1 character differs)")

    print(f"\nDigest of message {len(original):>9,} bytes : "
          f"{len(h_original.hex())} characters")
    print(f"Digest of file    {len(large_file):>9,} bytes : "
          f"{len(sha256_hex(large_file))} characters")

    # Repeat with random messages, changing 1 character each time
    results = []
    for _ in range(NUM_TRIALS):
        message = "".join(random.choices(string.ascii_letters, k=32))
        d1 = hashlib.sha256(message.encode()).digest()
        d2 = hashlib.sha256(change_one_char(message).encode()).digest()
        results.append(percent_bits_changed(d1, d2))

    print(f"\nAvalanche effect ({NUM_TRIALS} trials, "
          f"1 character changed)")
    print(f"Average bits changed : {statistics.mean(results):.1f}%")
    print(f"Lowest / highest     : {min(results):.1f}% / "
          f"{max(results):.1f}%")


# ==========================================================
# [2] HASHING FOR PASSWORDS: the same properties become a flaw
# ==========================================================
USERS = [
    ("Max", "abc123"),
    ("George", "qwerty"),
    ("Alice", "Rainy#Coffee_Morning7"),
    ("Bob", "abc123"),
    ("Jane", "12345678"),
]

# A small wordlist of commonly used passwords
WORDLIST = [
    "123456", "password", "12345678", "qwerty", "111111",
    "abc123", "admin123", "iloveyou", "welcome", "jogja2026",
]


def password_demo() -> None:
    # Lookup table: the hash of every wordlist entry, computed first
    lookup_table = {sha256_hex(w.encode()): w for w in WORDLIST}

    print("\n=== [2a] Passwords stored with plain SHA-256 ===")
    cracked = 0
    for name, pw in USERS:
        h = sha256_hex(pw.encode())
        guess = lookup_table.get(h)
        if guess:
            cracked += 1
        print(f"{name:<6} | {h[:24]}... | "
              f"lookup table: {guess or '-'}")
    print(f"Cracked without any new hashing: "
          f"{cracked} of {len(USERS)}")

    print("\n=== [2b] SHA-256 with a random salt per user ===")
    cracked = 0
    for name, pw in USERS:
        salt = os.urandom(16)
        h = sha256_hex(salt + pw.encode())
        if h in lookup_table:
            cracked += 1
        print(f"{name:<6} | salt {salt.hex()[:8]}... | {h[:24]}...")
    print(f"Cracked via lookup table: "
          f"{cracked} of {len(USERS)}")

    print("\n=== [2c] Guessing speed: SHA-256 vs bcrypt ===")
    salt = os.urandom(16)
    bcrypt_salt = bcrypt.gensalt(rounds=BCRYPT_COST)

    def guess_sha256(pw: bytes) -> bytes:
        return hashlib.sha256(salt + pw).digest()

    def guess_bcrypt(pw: bytes) -> bytes:
        return bcrypt.hashpw(pw, bcrypt_salt)

    # SHA-256 is tried 200,000 times, bcrypt only 3 times (it is slow)
    sha256_speed = guesses_per_second(guess_sha256, WORDLIST * 20000)
    bcrypt_speed = guesses_per_second(guess_bcrypt, WORDLIST[:3])

    results = [
        ("SHA-256 + salt", sha256_speed),
        (f"bcrypt cost {BCRYPT_COST}", bcrypt_speed),
    ]
    for name, speed in results:
        seconds = WORDLIST_SIZE / speed
        if seconds < 3600:
            duration = f"{seconds:,.0f} seconds"
        else:
            duration = f"{seconds / 86400:,.1f} days"
        print(f"{name:<15} | {speed:>12,.1f} guesses/sec "
              f"| {WORDLIST_SIZE:,} words: {duration}")


if __name__ == "__main__":
    integrity_demo()
    password_demo()
