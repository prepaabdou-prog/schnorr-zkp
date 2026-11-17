# Schnorr ZKP (work in progress)

My implementation of the Schnorr zero-knowledge proof in Python, written to learn
how zero-knowledge proofs work. Not secure for real use.

## Done

- Group generation (safe prime, subgroup of order q)
- Key generation and the interactive Schnorr protocol
- Secret extraction and simulator (soundness and zero-knowledge)
- Fiat-Shamir transform (non-interactive proof)
- Attacks: nonce reuse, baby-step giant-step (being tested)

## To do

- Benchmarks
- Study of post-quantum (lattice-based) zero-knowledge proofs

## Run

```
python3 test_schnorr.py
```