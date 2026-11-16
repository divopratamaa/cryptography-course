"""
Secure Chat Protocol Design: Ephemeral ECDH + Signatures + AES-GCM
==================================================================
A simulation of the key mechanism for a secure chat between
Alice and Bob:
  [1] Handshake without vs with authentication (MITM)
  [2] Modified messages and replayed messages
  [3] Identity key leaked after the session ends (forward secrecy)

Requirements: pip install cryptography
"""

import hashlib
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVE = ec.SECP256R1()
LABEL = b"securechat/v1"
ECDSA = ec.ECDSA(hashes.SHA256())


def to_bytes(public_key) -> bytes:
    # Turn a public key into bytes so it can be sent over the network
    return public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)


def fingerprint(public_key) -> str:
    # Short fingerprint that users compare with each other directly
    h = hashlib.sha256(to_bytes(public_key)).hexdigest()[:16]
    return " ".join(h[i:i + 4] for i in range(0, 16, 4))


class User:
    def __init__(self, name: str):
        self.name = name
        # Long-term identity key, used ONLY for signing
        self.identity = ec.generate_private_key(CURVE)
        # Identity public keys of contacts that have been verified
        self.contacts = {}

    def verify_contact(self, other: "User") -> None:
        # Fingerprints are compared once, for example by scanning a QR
        self.contacts[other.name] = other.identity.public_key()


# ==========================================================
# Key mechanism: handshake and session key
# ==========================================================
def make_hello(sender: User, eph_private) -> dict:
    # Send the ephemeral public key + an identity key signature
    eph = to_bytes(eph_private.public_key())
    data = LABEL + sender.name.encode() + eph
    sig = sender.identity.sign(data, ECDSA)
    return {"from": sender.name, "eph": eph, "sig": sig}


def check_hello(receiver: User, hello: dict) -> bool:
    # The signature must match the verified identity key
    public_key = receiver.contacts.get(hello["from"])
    if public_key is None:
        return False
    data = LABEL + hello["from"].encode() + hello["eph"]
    try:
        public_key.verify(hello["sig"], data, ECDSA)
        return True
    except InvalidSignature:
        return False


def session_key(eph_private, peer_eph: bytes,
                transcript: bytes) -> bytes:
    # ECDH produces a shared secret, HKDF derives the AES key
    peer_public = ec.EllipticCurvePublicKey.from_encoded_point(
        CURVE, peer_eph)
    shared = eph_private.exchange(ec.ECDH(), peer_public)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=LABEL + b"/session/" + transcript).derive(shared)


class Session:
    def __init__(self, key: bytes, me: str, peer: str):
        self.aes = AESGCM(key)
        self.me, self.peer = me, peer
        self.send_seq = 0
        self.last_seq = 0

    def send(self, text: str) -> dict:
        self.send_seq += 1
        nonce = os.urandom(12)
        # Sender, receiver, and sequence number are protected by GCM
        aad = f"{self.me}>{self.peer}#{self.send_seq}".encode()
        data = self.aes.encrypt(nonce, text.encode(), aad)
        return {"seq": self.send_seq, "nonce": nonce, "data": data}

    def receive(self, packet: dict) -> str:
        # A sequence number that was already received means a replay
        if packet["seq"] <= self.last_seq:
            raise ValueError("replay")
        aad = f"{self.peer}>{self.me}#{packet['seq']}".encode()
        text = self.aes.decrypt(packet["nonce"], packet["data"], aad)
        self.last_seq = packet["seq"]
        return text.decode()


def handshake(alice: User, bob: User, hello_a=None):
    # Alice starts, Bob replies, both check the signatures
    eph_a = ec.generate_private_key(CURVE)
    eph_b = ec.generate_private_key(CURVE)
    hello_a = hello_a or make_hello(alice, eph_a)
    if not check_hello(bob, hello_a):
        return None, hello_a, None
    hello_b = make_hello(bob, eph_b)
    if not check_hello(alice, hello_b):
        return None, hello_a, hello_b
    transcript = hello_a["eph"] + hello_b["eph"]
    k_a = session_key(eph_a, hello_b["eph"], transcript)
    k_b = session_key(eph_b, hello_a["eph"], transcript)
    # Ephemeral private keys are dropped once the session key exists
    del eph_a, eph_b
    return (k_a, k_b), hello_a, hello_b


# ==========================================================
# [1] MITM: ECDH without authentication vs with signatures
# ==========================================================
def mitm_demo(alice: User, bob: User) -> None:
    print("=== [1a] Unauthenticated ECDH, Mallory in the middle ===")
    eph_a = ec.generate_private_key(CURVE)
    eph_b = ec.generate_private_key(CURVE)
    eph_m1 = ec.generate_private_key(CURVE)
    eph_m2 = ec.generate_private_key(CURVE)
    pa = to_bytes(eph_a.public_key())
    pb = to_bytes(eph_b.public_key())
    pm1 = to_bytes(eph_m1.public_key())
    pm2 = to_bytes(eph_m2.public_key())
    # Mallory swaps Alice's and Bob's public keys with her own
    k_alice = session_key(eph_a, pm2, pa + pm2)
    k_mal_a = session_key(eph_m2, pa, pa + pm2)
    k_mal_b = session_key(eph_m1, pb, pm1 + pb)
    k_bob = session_key(eph_b, pm1, pm1 + pb)

    alice_session = Session(k_alice, "Alice", "Bob")
    packet = alice_session.send("Locker PIN is 78923")
    read = Session(k_mal_a, "Bob", "Alice").receive(packet)
    new_packet = Session(k_mal_b, "Alice", "Bob").send(read)
    received = Session(k_bob, "Bob", "Alice").receive(new_packet)
    print(f"Mallory reads      : {read}")
    print(f"Bob receives       : {received} (unaware of Mallory)")

    print("\n=== [1b] Handshake signed with identity keys ===")
    fp_alice = fingerprint(alice.identity.public_key())
    fp_bob = fingerprint(bob.identity.public_key())
    print(f"Alice fingerprint  : {fp_alice}")
    print(f"Bob fingerprint    : {fp_bob}")
    keys, _, _ = handshake(alice, bob)
    same = keys[0] == keys[1]
    print(f"Normal handshake   : same session key = {same}")

    # Mallory replaces the ephemeral public key in Alice's hello
    mallory = User("Mallory")
    fake = make_hello(mallory, eph_m1)
    fake["from"] = "Alice"
    keys, _, _ = handshake(alice, bob, hello_a=fake)
    status = "ACCEPTED" if keys else "REJECTED, handshake aborted"
    print(f"Swapped hello      : {status}")


# ==========================================================
# [2] Modified messages and replayed messages
# ==========================================================
def tamper_replay_demo(alice: User, bob: User) -> None:
    print("\n=== [2] Modified and replayed messages ===")
    (k_a, k_b), _, _ = handshake(alice, bob)
    alice_session = Session(k_a, "Alice", "Bob")
    bob_session = Session(k_b, "Bob", "Alice")

    packet = alice_session.send("Transfer Rp500,000 to Bob")
    print(f"Original message   : {bob_session.receive(packet)}")

    packet2 = alice_session.send("Confirm tomorrow morning")
    modified = dict(packet2, data=packet2["data"][:-1] + b"\x00")
    for label, p in [("Modified ciphertext", modified),
                     ("Replayed message", packet)]:
        try:
            bob_session.receive(p)
            print(f"{label:<19}: ACCEPTED")
        except InvalidTag:
            print(f"{label:<19}: REJECTED (InvalidTag)")
        except ValueError:
            print(f"{label:<19}: REJECTED (sequence number reused)")


# ==========================================================
# [3] Identity key leaked after the session ends
# ==========================================================
def forward_secrecy_demo(alice: User, bob: User) -> None:
    print("\n=== [3] Identity key leaked after the session ends ===")
    # Eve records the whole handshake and the old ciphertext
    (k_a, k_b), hello_a, hello_b = handshake(alice, bob)
    recording = Session(k_a, "Alice", "Bob").send("Safe PIN is 4821")
    (k2, _), _, _ = handshake(alice, bob)
    print(f"Session 1 key == session 2 key : {k_a == k2}")

    # A year later, Alice's and Bob's identity keys are stolen
    stolen = bob.identity
    transcript = hello_a["eph"] + hello_b["eph"]
    try:
        guess = session_key(stolen, hello_a["eph"], transcript)
        Session(guess, "Bob", "Alice").receive(recording)
        print("Opening the old recording      : SUCCEEDED")
    except InvalidTag:
        print("Opening the old recording      : FAILED (session key "
              "cannot be recomputed)")

    # But a stolen identity key can impersonate in a new session
    eph_eve = ec.generate_private_key(CURVE)
    eve = User("Alice")
    eve.identity = alice.identity
    passed = check_hello(bob, make_hello(eve, eph_eve))
    result = "SUCCEEDED" if passed else "FAILED"
    print(f"Impersonating in a new session : {result} "
          f"-> revoke the identity key")


if __name__ == "__main__":
    alice, bob = User("Alice"), User("Bob")
    # Registration: fingerprints are verified with each other once
    alice.verify_contact(bob)
    bob.verify_contact(alice)

    mitm_demo(alice, bob)
    tamper_replay_demo(alice, bob)
    forward_secrecy_demo(alice, bob)
