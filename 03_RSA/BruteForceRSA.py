"""
Brute-Force Attack Simulation on RSA
Goal: recover the private key using nothing but the leaked public key (n, e).

Attack flow:
- Factor n into p and q by brute force (trial division).
- Compute d with the Extended Euclidean algorithm (from RSA_Encrypt.py).
- Read the intercepted message with the recovered private key.
- Experiment: how factoring time grows as n gets bigger.
"""

import time
from RSA_Encrypt import mod_inverse, decrypt_text

# What the attacker has leaked/intercepted (from Example 3 in RSA_Encrypt.py)
PUBLIC_N = 10403
PUBLIC_E = 7
INTERCEPTED_CIPHERTEXT = [6642, 623, 9439, 623, 10355, 7716, 623]


def find_prime_factors(n):
    """
    Try every possible divisor from 2 up to sqrt(n).
    The first one that divides n evenly gives us p and q.
    Also returns how many attempts it took.
    """
    candidate = 2
    attempts = 0
    limit = int(n ** 0.5) + 1

    while candidate <= limit:
        attempts += 1
        if n % candidate == 0:
            other = n // candidate
            return candidate, other, attempts
        candidate += 1

    return None, None, attempts


def run_attack(n, e, ciphertext):
    print(f"=== RSA ATTACK SIMULATION (n={n}, e={e}) ===\n")
    print("What the attacker has:")
    print(f"  Public key : (e={e}, n={n})")
    print(f"  Ciphertext : {ciphertext}\n")

    # Step 1: factor n -> the only hard part
    p, q, attempts = find_prime_factors(n)
    if not p:
        print(f"n={n} looks prime and cannot be factored. Attack failed.")
        return
    print(f"Step 1 - Prime factors found   -> p={p}, q={q} ({attempts} attempts)")

    # Step 2: compute the totient, exactly like the key owner does
    totient_n = (p - 1) * (q - 1)
    print(f"Step 2 - Totient(n) = (p-1)(q-1) = {totient_n}")

    # Step 3: compute d with Extended Euclid (the same formula the key owner uses)
    try:
        d = mod_inverse(e, totient_n)
    except ValueError:
        print("Private key (d) not found. e may be invalid.")
        return
    print(f"Step 3 - Private key recovered -> d={d}")

    # Step 4: read the intercepted message
    message = decrypt_text(ciphertext, (d, n))
    print(f"Step 4 - Message decrypted     -> {message}")

    print("\n--- Key pair summary ---")
    print(f"Public  key : (n={n}, e={e})")
    print(f"Private key : (n={n}, d={d})")


def scaling_test():
    """
    Experiment: the bigger n gets, the more factoring attempts are needed.
    Each prime pair is roughly 10x bigger than the one before it.
    """
    prime_pairs = [
        (101, 103),
        (1009, 1013),
        (10007, 10009),
        (100003, 100019),
        (1000003, 1000033),
        (10000019, 10000079),
    ]

    print("\n=== EXPERIMENT: SIZE OF n vs FACTORING TIME ===")
    print(f"{'Digits':>6} | {'n':>15} | {'Attempts':>10} | {'Time (s)':>9}")
    print("-" * 50)

    for p, q in prime_pairs:
        n = p * q
        start = time.perf_counter()
        _, _, attempts = find_prime_factors(n)
        elapsed = time.perf_counter() - start
        print(f"{len(str(n)):>6} | {n:>15} | {attempts:>10} | {elapsed:>9.5f}")


if __name__ == "__main__":
    run_attack(PUBLIC_N, PUBLIC_E, INTERCEPTED_CIPHERTEXT)
    scaling_test()
