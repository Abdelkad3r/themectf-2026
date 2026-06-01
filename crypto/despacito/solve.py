#!/usr/bin/env python3
"""End-to-end solver for the THEM?! CTF 2026 "Despacito" (crypto) challenge.

`ques.py` is a one-shot DES-ECB encryptor:

    key = bytes.fromhex("E1E1E1E1F0F0F0F0")
    ciphertext = base64(DES_ECB_encrypt(pad(flag, b"*"), key))

`output.txt` is `T/tGpZNyHdhnf1oxwRmMPFcLiH//AfZdTpmYdp8daU0=`.

The trick is the key. DES has exactly four "weak keys" -- keys for which
the per-round subkeys are all identical so the cipher is its own inverse
(`E_k(E_k(P)) == P`):

    0101010101010101
    FEFEFEFEFEFEFEFE
    1F1F1F1F0E0E0E0E
    E0E0E0E0F1F1F1F1   <-- the relevant one

The handout supplies `E1E1E1E1F0F0F0F0`. Compare it byte-by-byte against
`E0E0E0E0F1F1F1F1`:

    E1 = E0 + 1   (LSB toggled)
    F0 = F1 - 1   (LSB toggled)

Every byte differs in exactly one bit -- the *parity bit*. DES strips
each byte's LSB during key scheduling (Permuted Choice 1 keeps only the
56 high bits), so `E1E1E1E1F0F0F0F0` and `E0E0E0E0F1F1F1F1` expand to
the *same* 56-bit effective key. The supplied key is the textbook weak
key in disguise.

With a weak key, decryption == encryption. Running the same operation
on the base64-decoded ciphertext yields the plaintext directly --
exactly 32 bytes, a clean 4-block multiple, so the `*`-pad loop in
`pad()` never fired and the output is the verbatim flag.

  $ ./solve.py
  THEM?!CTF{D3S_4774K_W3S_AW3S0M3}
"""
import argparse
import base64
import sys
from pathlib import Path

try:
    from Crypto.Cipher import DES
except ImportError:
    print("requires pycryptodome  -- pip install pycryptodome", file=sys.stderr)
    sys.exit(1)


CIPHERTEXT_B64 = "T/tGpZNyHdhnf1oxwRmMPFcLiH//AfZdTpmYdp8daU0="
KEY            = bytes.fromhex("E1E1E1E1F0F0F0F0")

# The four DES weak keys, for the weak-key check.
DES_WEAK_KEYS = {
    bytes.fromhex("0101010101010101"),
    bytes.fromhex("FEFEFEFEFEFEFEFE"),
    bytes.fromhex("1F1F1F1F0E0E0E0E"),
    bytes.fromhex("E0E0E0E0F1F1F1F1"),
}


def strip_parity_bits(k: bytes) -> bytes:
    """Zero out each byte's LSB (DES parity bit)."""
    return bytes(b & 0xFE for b in k)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ciphertext", "-c", default=CIPHERTEXT_B64,
                    help="base64 ciphertext (default: handout's)")
    ap.add_argument("--key", "-k", default=KEY.hex(),
                    help="hex key (default: handout's E1E1E1E1F0F0F0F0)")
    args = ap.parse_args()

    key = bytes.fromhex(args.key)
    ct  = base64.b64decode(args.ciphertext)

    weak_key_match = strip_parity_bits(key) in {strip_parity_bits(w) for w in DES_WEAK_KEYS}
    sys.stderr.write(f"[+] key {key.hex()}  -> weak after parity-strip? {weak_key_match}\n")

    pt = DES.new(key, DES.MODE_ECB).decrypt(ct)
    # weak-key self-inverse cross-check
    pt2 = DES.new(key, DES.MODE_ECB).encrypt(ct)
    assert pt == pt2, "weak-key self-inverse property failed - check the key"

    sys.stderr.write(f"[+] decrypt == encrypt (weak-key cross-check passes)\n")

    # Strip trailing "*" padding the challenge added.
    flag = pt.rstrip(b"*")
    print(flag.decode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
