# Crypto vectors

These vectors are the external reference for `philharmonic-policy` SCK and
`pht_` token crypto behavior.

- `gen_sck.py` and `gen_pht.py` reproduce the expected values with Python 3.
- `gen_sck.py` needs `cryptography` (pyca/OpenSSL backend).
- If RustCrypto behavior ever differs from these vectors, the Rust
  implementation is wrong; do not update vectors to match drift.
- `cargo test` does not execute Python. The committed source-of-truth vectors
  are embedded as hex literals in `tests/crypto_vectors.rs`.

Re-run for audit:

```sh
cd philharmonic-policy/tests/crypto_vectors
python3 ./gen_sck.py
python3 ./gen_pht.py
```
