"""
Week 1 - Security Mindset (Cryptography)
========================================
Developed from the week 1 class example (Base64 decoding + SHA-256 hashing)
into a three-part tutorial:
  [1] Base64 is not encryption -> reversed without any key.
  [2] Plain SHA-256 is still weak -> cracked by a dictionary attack.
  [3] The fix: per-user salt + slow hashing (PBKDF2).
"""

import base64
import hashlib
import hmac
import os


# ==========================================================
# [1] Base64 is not encryption
# Wrap the encoding in functions, then show it reverses WITHOUT a key.
# ==========================================================
def encode_base64(password: str) -> str:
    # Note: it only takes the password. There is NO key parameter.
    return base64.b64encode(password.encode("utf-8")).decode("utf-8")


def decode_base64(stored: str) -> str:
    # The attacker simply runs the reverse operation. Still no key.
    return base64.b64decode(stored).decode("utf-8")


def demo_base64(users: dict) -> None:
    # The server "secures" each password before saving it to the database.
    database = {name: encode_base64(pw) for name, pw in users.items()}

    print("=== [1] Contents of the password_stored column ===")
    for name, stored in database.items():
        print(f"{name:8s} | {stored}")

    # The attacker has obtained a copy of the database.
    print("\n=== [1] Attacker recovers every password ===")
    for name, stored in database.items():
        print(f"{name:8s} | {stored:14s} -> {decode_base64(stored)}")


# ==========================================================
# [2] Plain SHA-256 can still be cracked
# The SHA-256 hashes fall to a dictionary attack.
# ==========================================================
def hash_sha256(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def dictionary_attack(hashed_db: dict, wordlist: list) -> None:
    # The attacker precomputes a lookup table: hash -> password for every word.
    table = {hash_sha256(word): word for word in wordlist}

    print("\n=== [2] Dictionary attack on plain SHA-256 hashes ===")
    for name, h in hashed_db.items():
        guessed = table.get(h, "[not in wordlist]")
        print(f"{name:8s} | {h[:24]}... -> {guessed}")


def demo_sha256(users: dict) -> None:
    hashed_db = {name: hash_sha256(pw) for name, pw in users.items()}

    print("\n=== [2] Same password, same hash ===")
    for name, h in hashed_db.items():
        print(f"{name:8s} | {h[:24]}...")

    # A tiny wordlist of common passwords. Real attackers use millions.
    wordlist = ["123456", "password", "qwerty", "user123", "admin", "abc123!"]
    dictionary_attack(hashed_db, wordlist)


# ==========================================================
# [3] The fix: unique salt per user + slow hashing (PBKDF2)
# ==========================================================
ITERATIONS = 600_000  # Repeat the hash many times so every guess is expensive.


def store_password(password: str) -> tuple:
    salt = os.urandom(16)  # Random 16-byte salt, different for every user.
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return salt, digest    # Only the salt and the hash go into the database.


def check_login(password_input: str, salt: bytes, digest: bytes) -> bool:
    # The server never "opens" the hash. It recomputes it and compares.
    recomputed = hashlib.pbkdf2_hmac("sha256", password_input.encode("utf-8"), salt, ITERATIONS)
    return hmac.compare_digest(recomputed, digest)  # Constant-time comparison.


def demo_pbkdf2(users: dict) -> None:
    database = {name: store_password(pw) for name, pw in users.items()}

    print("\n=== [3] Database with salt + PBKDF2 (first 16 hex characters) ===")
    for name, (salt, digest) in database.items():
        print(f"{name:8s} | salt={salt.hex()[:16]}... | hash={digest.hex()[:16]}...")

    salt, digest = database["bob"]
    print("\n=== [3] Login check for bob (password 'password') ===")
    print(f"Input 'password'  -> {check_login('password', salt, digest)}")
    print(f"Input 'Password1' -> {check_login('Password1', salt, digest)}")


if __name__ == "__main__":
    # bob and dave deliberately share the same password to prove a point.
    users = {"alice": "user123", "bob": "password", "charlie": "abc123!", "dave": "password"}

    demo_base64(users)
    demo_sha256(users)
    demo_pbkdf2(users)
