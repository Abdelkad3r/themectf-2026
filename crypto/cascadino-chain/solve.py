#!/usr/bin/env python3
"""End-to-end solver for the THEM?! CTF 2026 "Cascadino Chain" (crypto) challenge.

Four hex ciphertexts and a riddle:

    "I built an unbreakable encryption chain, each key protects the next
     and the last loops back to the start. There's no way in... right?"

The chain is a four-stage closed XOR cycle (each ci same length L = 42):

    c1 = flag XOR k1            (k1 protects flag)
    c2 = k1   XOR k2            (k2 protects k1)
    c3 = k2   XOR k3            (k3 protects k2)
    c4 = k3   XOR flag          (k3 protects flag again, closing the loop)

Two structural tells fall straight out of the hex:

  *  c2 and c3 are 4-byte periodic.  k_i XOR k_j periodic means the keys
     themselves are short (period | 4) -- so k1, k2, k3 are 4-byte keys
     repeated to length 42.  The repeated patterns are:
        c2 = "0e021b00" repeating  =>  k1 XOR k2 = 0x0e021b00
        c3 = "18050402" repeating  =>  k2 XOR k3 = 0x18050402

  *  c1 XOR c4 is also 4-byte periodic and equals c2 XOR c3 = "16071f02".
     That's k1 XOR k3 -- the closure constraint of the cycle.  It also
     means c1 XOR c2 XOR c3 XOR c4 == 0 -- the "way in" the riddle warns
     about ("there's no way in") is a four-way XOR sum that gives no
     information at all about the flag.

The actual way in is the flag format.  THEM?! CTF flags begin with
"THEM?!CTF{" -- ten known plaintext bytes.  Taking the first four:

    k1 = c1[0:4] XOR "THEM" = 36^54, 27^48, 3f^45, 22^4d = 62 6f 7a 6f = "bozo"

The rest of the prefix verifies it (k1 is 4-byte periodic, so positions
4..9 reproduce "?!CTF{" with the same "bozo" pattern).  Pulling on the
thread:

    k2 = k1 XOR (c2 pattern) = "bozo" XOR 0x0e021b00 = "lmao"
    k3 = k2 XOR (c3 pattern) = "lmao" XOR 0x18050402 = "them"

flag = c1 XOR ("bozo" * 11)[:42] = THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}

  $ ./solve.py
  THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}
"""
import argparse
import sys
from pathlib import Path


C1 = bytes.fromhex("36273f225d4e393b2414025f1030025f1030025f10301907035e145e0c082508520a0930001d081d1012")
C2 = bytes.fromhex("0e021b000e021b000e021b000e021b000e021b000e021b000e021b000e021b000e021b000e021b000e02")
C3 = bytes.fromhex("180504021805040218050402180504021805040218050402180504021805040218050402180504021805")
C4 = bytes.fromhex("202020204b49263932131d5d06371d5d06371d5d0637060515590b5c1a0f3a0a440d1632161a171f0615")

PREFIX = b"THEM?!CTF{"   # known plaintext from the THEM?! CTF flag format


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def extend(key: bytes, length: int) -> bytes:
    return bytes(key[i % len(key)] for i in range(length))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verify", action="store_true",
                    help="print the recovered keys and the closure check")
    args = ap.parse_args()

    L = len(C1)
    assert L == len(C2) == len(C3) == len(C4), "ciphertext length mismatch"

    # 1. closure check (no information on its own, but confirms the chain shape)
    assert all(a ^ b ^ c ^ d == 0 for a, b, c, d in zip(C1, C2, C3, C4)), \
        "c1 ^ c2 ^ c3 ^ c4 != 0 -- chain is not a closed XOR cycle"

    # 2. crib-recovered k1 from the flag prefix
    k1 = xor(C1[:4], PREFIX[:4])

    # 3. derive k2, k3 from the periodic XOR patterns of c2, c3
    k2 = xor(k1, C2[:4])
    k3 = xor(k2, C3[:4])

    # 4. consistency: c1[4..9] under "bozo" must equal "?!CTF{"
    early = xor(C1[:10], extend(k1, 10))
    assert early == PREFIX, f"prefix mismatch: {early!r} vs {PREFIX!r}"

    # 5. flag
    flag = xor(C1, extend(k1, L))

    if args.verify:
        sys.stderr.write(f"[+] k1 = {k1!r}\n")
        sys.stderr.write(f"[+] k2 = {k2!r}\n")
        sys.stderr.write(f"[+] k3 = {k3!r}\n")
        # c4 = k3 XOR flag (closure check from the OTHER side)
        c4_back = xor(flag, extend(k3, L))
        assert c4_back == C4, "c4 reconstruction failed"
        sys.stderr.write("[+] c4 = flag XOR k3 verified\n")

    print(flag.decode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
