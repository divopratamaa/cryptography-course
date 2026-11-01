"""
RSA Encryption/Decryption - The Math Behind Cryptography
Week 3: Modulo, Prime Numbers, Modular Inverse, Trapdoor Function

Usage: run this file, or import its functions to try other values
of p, q, e and the message (m).

What this program covers:
- Example 1: an RSA calculation with small numbers (p = 11, q = 13, m = 9).
- Example 2: the p = 101, q = 103 key that BruteForceRSA.py attacks.
- Example 3: TEXT encryption/decryption, character by character, with the key from Example 2.
"""


def is_prime(n):
    """Check whether n is a prime number."""
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


def gcd(a, b):
    """Greatest Common Divisor using the Euclidean algorithm."""
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd
    """
    if b == 0:
        return a, 1, 0
    gcd_val, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd_val, x, y


def mod_inverse(e, phi_n):
    """
    Find the modular inverse of e modulo phi_n, i.e. the d
    that satisfies (e * d) mod phi_n = 1.
    """
    g, x, _ = extended_gcd(e, phi_n)
    if g != 1:
        raise ValueError(f"No inverse exists because gcd({e}, {phi_n}) = {g} (not 1)")
    return x % phi_n


def generate_keys(p, q, e=None):
    """
    Build an RSA public and private key from two primes p and q.
    If e is not given, the smallest valid odd value is picked automatically.
    """
    if not is_prime(p) or not is_prime(q):
        raise ValueError("p and q must be prime numbers!")
    if p == q:
        raise ValueError("p and q must be different!")

    n = p * q
    phi_n = (p - 1) * (q - 1)

    if e is None:
        # Find the smallest valid e: 1 < e < phi_n and gcd(e, phi_n) = 1
        e = 3
        while gcd(e, phi_n) != 1:
            e += 2
    else:
        if not (1 < e < phi_n):
            raise ValueError(f"e must be between 1 and {phi_n}")
        if gcd(e, phi_n) != 1:
            raise ValueError(f"gcd({e}, {phi_n}) != 1, e is not valid")

    d = mod_inverse(e, phi_n)

    public_key = (e, n)
    private_key = (d, n)

    return {
        "p": p,
        "q": q,
        "n": n,
        "phi_n": phi_n,
        "e": e,
        "d": d,
        "public_key": public_key,
        "private_key": private_key,
    }


def encrypt(m, public_key):
    """Encrypt message m: c = m^e mod n"""
    e, n = public_key
    if m >= n:
        raise ValueError(f"Message m must be smaller than n ({n})")
    return pow(m, e, n)


def decrypt(c, private_key):
    """Decrypt ciphertext c: m = c^d mod n"""
    d, n = private_key
    return pow(c, d, n)


# ==========================================================
# TEXT ENCRYPTION
# RSA works on numbers, so each character is first turned into
# its ASCII code (e.g. 'A' -> 65) and then encrypted.
# Requirement: n must be larger than the biggest character code (> 127).
# ==========================================================
def encrypt_text(text, public_key):
    """Encrypt text character by character; returns a list of numbers."""
    return [encrypt(ord(ch), public_key) for ch in text]


def decrypt_text(cipher_list, private_key):
    """Decrypt a list of numbers back into text."""
    return "".join(chr(decrypt(c, private_key)) for c in cipher_list)


def print_rsa_report(p, q, e=None, message=None):
    """Print the full RSA calculation, step by step."""
    print("=" * 60)
    print(f"RSA WORKED EXAMPLE: p = {p}, q = {q}")
    print("=" * 60)

    keys = generate_keys(p, q, e)

    print("\nStep 1: Choose two prime numbers")
    print(f"  p = {keys['p']}")
    print(f"  q = {keys['q']}")

    print("\nStep 2: Compute n and phi(n)")
    print(f"  n = p * q = {keys['p']} * {keys['q']} = {keys['n']}")
    print(f"  phi(n) = (p-1)(q-1) = {keys['p']-1} * {keys['q']-1} = {keys['phi_n']}")

    print("\nStep 3: Choose the public exponent (e)")
    print(f"  e = {keys['e']}")
    print(f"  Check: gcd({keys['e']}, {keys['phi_n']}) = {gcd(keys['e'], keys['phi_n'])}")

    print("\nStep 4: Find the private exponent (d)")
    print(f"  Condition: {keys['e']} * d = 1 (mod {keys['phi_n']})")
    print(f"  d = {keys['d']}")
    check = (keys['e'] * keys['d']) % keys['phi_n']
    print(f"  Verify: ({keys['e']} * {keys['d']}) mod {keys['phi_n']} = {check}")

    print("\nRSA key pair:")
    print(f"  Public key  (e, n) = {keys['public_key']}")
    print(f"  Private key (d, n) = {keys['private_key']}")

    if message is not None:
        print("\nStep 5: Encrypt & decrypt")
        m = message
        c = encrypt(m, keys['public_key'])
        m_back = decrypt(c, keys['private_key'])

        print(f"  Original message  m = {m}")
        print(f"  Encrypt: c = m^e mod n = {m}^{keys['e']} mod {keys['n']} = {c}")
        print(f"  Decrypt: m = c^d mod n = {c}^{keys['d']} mod {keys['n']} = {m_back}")

        status = "VALID (message recovered)" if m == m_back else "FAILED (mismatch!)"
        print(f"  Status: {status}")

    print("=" * 60)
    return keys


if __name__ == "__main__":
    # Example 1: p = 11, q = 13 (result: e = 7, d = 103, c = 48)
    print_rsa_report(p=11, q=13, message=9)

    print()

    # Example 2: p = 101, q = 103 (this is the key attacked in BruteForceRSA.py)
    keys = print_rsa_report(p=101, q=103, message=2)

    # Example 3: encrypt text with the key from Example 2
    message = "RAHASIA"  # Indonesian for "secret"
    cipher = encrypt_text(message, keys["public_key"])
    decrypted = decrypt_text(cipher, keys["private_key"])

    print("\nText encryption (character by character)")
    print(f"  Original    : {message}")
    print(f"  ASCII codes : {[ord(ch) for ch in message]}")
    print(f"  Ciphertext  : {cipher}")
    print(f"  Decrypted   : {decrypted}")
