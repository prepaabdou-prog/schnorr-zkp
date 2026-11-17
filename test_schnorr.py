"""Run:  python3 test_schnorr.py        (all steps)
        python3 test_schnorr.py 3      (only step 3)
"""
import sys
import secrets
from number_theory import is_probable_prime, modpow
import group as G
import schnorr as S
import fiat_shamir as F
import attacks as A


def step1():
    p, q, g = G.generate_group(64)
    assert p.bit_length() == 64, "p must have 64 bits"
    assert p == 2 * q + 1, "p must equal 2q + 1"
    assert is_probable_prime(p) and is_probable_prime(q), "p and q must be prime"
    assert g != 1 and modpow(g, q, p) == 1, "g must have order q"
    assert G.in_subgroup(g, p, q)
    assert not G.in_subgroup(p - 1, p, q), "p-1 has order 2, it is not in the subgroup"
    assert not G.in_subgroup(1, p, q), "1 is excluded"


def step2():
    grp = G.generate_group(64)
    p, q, g = grp
    x, y = S.keygen(grp)
    assert 1 <= x <= q - 1
    assert y == modpow(g, x, p)
    assert S.keygen(grp)[0] != S.keygen(grp)[0], "keys must be random"


def step3():
    grp = G.generate_group(64)
    p, q, g = grp
    x, y = S.keygen(grp)
    for _ in range(10):
        P, V = S.Prover(grp, x), S.Verifier(grp, y)
        t = P.commit()
        c = V.challenge()
        assert 0 <= c < q
        s = P.respond(c)
        assert V.check(t, s), "honest prover must be accepted"
    # tampered answer
    P, V = S.Prover(grp, x), S.Verifier(grp, y)
    t = P.commit(); c = V.challenge(); s = P.respond(c)
    assert not V.check(t, (s + 1) % q), "wrong answer must be rejected"
    # malleability
    P, V = S.Prover(grp, x), S.Verifier(grp, y)
    t = P.commit(); c = V.challenge(); s = P.respond(c)
    assert not V.check(t, s + q), "s >= q must be rejected"
    # prover without the secret
    wrong_x = (x + 12345) % q or 1
    for _ in range(10):
        P, V = S.Prover(grp, wrong_x), S.Verifier(grp, y)
        t = P.commit(); c = V.challenge()
        assert not V.check(t, P.respond(c)), "prover with the wrong secret must fail"


def step4():
    grp = G.generate_group(64)
    p, q, g = grp
    x, y = S.keygen(grp)
    # soundness / extraction
    P = S.Prover(grp, x)
    P.commit()
    c1, c2 = 1111, 2222
    s1, s2 = P.respond(c1), P.respond(c2)  # same r, two challenges
    assert S.extract_secret(grp, c1, s1, c2, s2) == x, "extraction must return x"
    # zero-knowledge / simulation
    for _ in range(10):
        t, c, s = S.simulate(grp, y)
        assert modpow(g, s, p) == t * modpow(y, c, p) % p, "simulated transcript must verify"


def step5():
    grp = G.generate_group(64)
    p, q, g = grp
    x, y = S.keygen(grp)
    c = F.challenge_hash(grp, y, 5, b"m")
    assert 0 <= c < q and c == F.challenge_hash(grp, y, 5, b"m"), "hash must be deterministic in [0,q)"
    assert c != F.challenge_hash(grp, y, 5, b"other"), "message must be hashed"
    assert c != F.challenge_hash(grp, y, 6, b"m"), "t must be hashed"
    assert c != F.challenge_hash(grp, modpow(y, 2, p), 5, b"m"), "y must be hashed (whole statement)"
    proof = F.prove(grp, x, y, b"hello")
    assert F.verify(grp, y, proof, b"hello")
    assert not F.verify(grp, y, proof, b"hellO"), "wrong message must fail"
    t, s = proof
    assert not F.verify(grp, y, (t, (s + 1) % q), b"hello"), "tampered proof must fail"
    assert not F.verify(grp, y, (t, s + q), b"hello"), "s >= q must fail"
    assert F.prove(grp, x, y, b"hello") != proof, "two proofs must differ (random r)"
    x2, y2 = S.keygen(grp)
    assert not F.verify(grp, y2, proof, b"hello"), "proof must not verify under another key"


def step6():
    grp = G.generate_group(64)
    p, q, g = grp
    x, y = S.keygen(grp)
    r = secrets.randbelow(q - 1) + 1
    p1 = F.prove(grp, x, y, b"first", r=r)
    p2 = F.prove(grp, x, y, b"second", r=r)
    assert p1[0] == p2[0], "same r must give same t"
    assert A.recover_from_nonce_reuse(grp, y, b"first", p1, b"second", p2) == x


def step7():
    grp = G.generate_group(40)
    p, q, g = grp
    x, y = S.keygen(grp)
    found = A.dlog_bsgs(grp, y)
    assert modpow(g, found, p) == y, "g^found must equal y"


STEPS = {1: step1, 2: step2, 3: step3, 4: step4, 5: step5, 6: step6, 7: step7}

if __name__ == "__main__":
    wanted = [int(a) for a in sys.argv[1:]] or sorted(STEPS)
    for n in wanted:
        try:
            STEPS[n]()
            print(f"[OK]   step {n}")
        except NotImplementedError as e:
            print(f"[TODO] step {n}: {e}")
        except AssertionError as e:
            print(f"[FAIL] step {n}: {e}")
        except Exception as e:
            print(f"[ERR]  step {n}: {type(e).__name__}: {e}")
