from number_theory import modinv, modpow
from fiat_shamir import challenge_hash
from math import isqrt


def recover_from_nonce_reuse(group, y, msg1, proof1, msg2, proof2):

    p, q, g = group
    t1, s1 = proof1
    t2, s2 = proof2
    c1 = challenge_hash(group, y, t1, msg1)
    c2 = challenge_hash(group, y, t2, msg2)
    return (s1 - s2) * modinv(c1 - c2, q) % q
  


def dlog_bsgs(group, y):
    p, q, g = group
    m = isqrt(q) + 1

    # baby steps : table[g^j] = j
    table = {}
    cur = 1
    for j in range(m):
        table[cur] = j
        cur = cur * g % p

    # giant steps : on cherche y * (g^-m)^i dans la table
    factor = modinv(modpow(g, m, p), p)   # g^(-m) mod p
    gamma = y
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]   # x = i*m + j
        gamma = gamma * factor % p
    return None
  
