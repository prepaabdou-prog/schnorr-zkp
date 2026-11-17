"""Step 5: Fiat-Shamir transform = non-interactive proof (a Schnorr signature)."""
import hashlib
import secrets
from number_theory import modpow
from group import in_subgroup


def challenge_hash(group, y, t, msg):
    p, q, g = group
    n = (p.bit_length() + 7) // 8         
    h = hashlib.sha256()
    for value in (p, q, g, y, t):
        h.update(value.to_bytes(n, "big"))
    h.update(msg)
    return int.from_bytes(h.digest(), "big") % q


def prove(group, x, y, msg=b"", r=None):
    p, q, g = group
    if r is None:
        r = secrets.randbelow(q - 1) + 1
    t = modpow(g, r, p)
    c = challenge_hash(group, y, t, msg)
    s = (r + c * x) % q
    return t, s


def verify(group, y, proof, msg=b""):
    p, q, g = group
    t, s = proof
    if not in_subgroup(t, p, q):
        return False
    if s < 0 or s >= q:
        return False
    c = challenge_hash(group, y, t, msg)
    return modpow(g, s, p) == t * modpow(y, c, p) % p