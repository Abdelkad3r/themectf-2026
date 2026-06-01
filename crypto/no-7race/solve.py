#!/usr/bin/env python3
"""End-to-end solver for the THEM?! CTF 2026 "No 7race" (crypto) challenge.

challenge.py reads `flag.txt`, treats it as a big-endian integer `a`,
multiplies by 2^77777, and accepts the flag iff the *decimal string* of
the product ends with a fixed 155-character suffix:

    a = int.from_bytes(flag, 'big')
    b = a << 77777                          #  i.e. a * 2^77777
    if not str(b).endswith(TARGET_155): exit()

Where TARGET_155 is the printed 155-character decimal literal in the
handout. The challenge is to recover `a` (the flag bytes) from this
constraint alone.

Recasting "decimal suffix" as arithmetic: the last 155 decimal digits
of `b` are `b mod 10^155`, so the constraint is

    a * 2^77777   ≡   target   (mod 10^155)

with `target = int(TARGET_155)` (≈ 3.08·10^153, since the literal has
a leading zero).

10^155 factors cleanly:  10^155 = 2^155 * 5^155.  CRT it.

  * mod 2^155:   77777 ≫ 155, so `a * 2^77777 ≡ 0  (mod 2^155)`.
                 The constraint demands `target ≡ 0 (mod 2^155)` — and
                 numerically it is (target ends in 155 trailing zeros…
                 actually it ends in the 155-digit decimal suffix shown,
                 which is itself divisible by 2^155 because the leading
                 decimal digits encode that suffix; the script verifies
                 this with `target % 2**155 == 0`). This component gives
                 us *no* information about `a` (every `a` satisfies it).

  * mod 5^155:   2 is coprime to 5, so 2^77777 is invertible mod 5^155.
                 Compute its inverse via `pow(2, -77777, 5**155)` and
                 solve  a ≡ target * (2^77777)^{-1}  (mod 5^155).
                 This pins `a` down to a *unique* residue class of size
                 5^155 ≈ 2^359.7.

The flag is at most 50 bytes (the handout's own length gate), so
`a < 2^400` but also `a < 2^(50*8) = 2^400`. The single residue class
mod 5^155 contains at most one 50-byte value: just convert
`a mod 5^155` straight to bytes and check it. It comes out exactly
32 bytes of printable ASCII:

    THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}

  $ ./solve.py
  THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}
"""
import argparse
import sys
from pathlib import Path

# str(b)/int(str) for huge integers needs the digit-limit unlocked, just
# like the original challenge does.
sys.set_int_max_str_digits(1_000_000)

# The 155-decimal-digit suffix the handout checks against
# (leading zero is significant in the equality but absorbed by `int(...)`).
TARGET_SUFFIX = (
    "03081127692533913997381228658418928780421416188103339458770036280"
    "397929450297959557812089439331054492922876854076547798835969658432"
    "397983993314299716042752"
)

SHIFT = 77777


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default=TARGET_SUFFIX,
                    help="155-digit decimal suffix (default: handout's)")
    ap.add_argument("--shift", type=int, default=SHIFT,
                    help="left shift amount (default: 77777)")
    args = ap.parse_args()

    target = int(args.target)
    N = len(args.target)
    mod10 = 10 ** N
    mod2  = 2  ** N
    mod5  = 5  ** N

    sys.stderr.write(f"[+] target has {N} decimal digits\n")
    sys.stderr.write(f"[+] working modulus is 10^{N} = 2^{N} * 5^{N}\n")

    # Sanity check: the mod-2^N component must be zero (shift swamps the binary).
    assert target % mod2 == 0, \
        f"target % 2^{N} != 0 -- shift {args.shift} doesn't dominate"

    # Recover a mod 5^N via the multiplicative inverse of 2^shift mod 5^N.
    inv = pow(2, -args.shift, mod5)
    a_mod = (target * inv) % mod5

    # Convert to bytes (big-endian, just enough to hold the residue).
    nbytes = (a_mod.bit_length() + 7) // 8
    flag = a_mod.to_bytes(nbytes, "big")
    sys.stderr.write(f"[+] recovered a mod 5^{N}: {nbytes} bytes\n")

    # Verify the constraint holds end-to-end.
    a = int.from_bytes(flag, "big")
    assert str(a << args.shift).endswith(args.target), \
        "round-trip check failed - shift/target mismatch?"

    print(flag.decode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
