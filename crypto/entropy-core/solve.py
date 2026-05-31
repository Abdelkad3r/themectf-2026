#!/usr/bin/env python3
"""End-to-end solver for the THEM?! CTF 2026 "Entropy Core" (rev) challenge.

`entropy_core.exe` is a Windows PE32+ console binary built with MinGW. The
visible interface is a single prompt -- "insert star key" -- followed by
either "access accepted" or "warp drift -- reactor SCRAM" depending on a
112-byte (in input length terms it's actually 36) verification routine.

Under the hood the binary is a thin C wrapper around a register VM. A
284-byte "IMAGE" blob in `.rdata` (VA 0x140005260) is `rep movsq`'d into
the stack at `rbp+0x80` and then interpreted by a `cmpb $0x61` dispatch
loop with a 98-entry jump table at 0x1400050c0. The VM has:

  - 16 64-bit registers at `rsp+0x20` (indexed by low nibble of bytes)
  - A 0xFFF0-byte stack inside the same buffer
  - 30 active opcodes:
      * 0x10  LD imm64                       (10 bytes)
      * 0x11  MOV                            (3)
      * 0x12-0x17  ADD SUB MUL XOR AND OR    (4, three register args)
      * 0x18-0x1B  SHL SHR ROL ROR           (4, byte-2 reg, byte-3 IS the shift count, not a register)
      * 0x20-0x23  LDB LDQ STB STQ           (5, indexed by R[idx]+u16)
      * 0x30/0x31  PUSH/POP                  (2)
      * 0x40-0x46  JMP JZ JNZ JEQ JNE CALL RET
      * 0x50/0x51  RC4_KSA / RC4_PRGA byte
      * 0x60/0x61  GETCHAR / PUTCHAR
      * 0x00       HALT (default branch -> exit and print success/fail)
      * 0x02       NOP-by-1

The bytecode reads 36 input bytes, runs each one through a per-byte hash
that mixes the input into an evolving 64-bit state R10 and compares its
low byte against a 36-byte ciphertext stored at IMAGE offset 0xf8.

Per byte (R10 starts as 0xcafebabedeadbeef, R11 is the counter):

    R1 = getchar
    R2 = RC4_next_byte
    R4 = R1 * 0x0101010101010101            # replicate input across 8 bytes
    R10 ^= R4
    R6 = R11 + 1
    R7 = R2 * R6                            # RC4 byte times one-based counter
    R10 += R7
    R10 *= 0x9e3779b97f4a7c15               # golden-ratio constant
    R8 = ROL(R10, 0x17)                     # CONSTANT shift of 23 - see traps
    R10 ^= R8
    if (R10 & 0xff) != ciphertext[R11]: jump to FAIL path

Two static-analysis traps:

  1.  The RC4 key is NOT the obvious 232-byte spread between offsets 0x10
      and 0xf8. The KSA handler computes its key-byte address as
      `bytecode[(i % 16) + R[r9]]` where R[r9] = R0 = 232 (= 0xe8). So the
      *actual* key is the 16-byte block at IMAGE[0xe8..0xf8] -- the literal
      string "EntropyCoreV1!\\0\\0" (the visible token followed by two pad
      zeros). Pick that up and the rest follows.

  2.  The ROL/SHL/SHR/ROR handlers DO NOT load a register for the shift
      count. There is no `andl $0xf, %ecx` followed by `movq 0x20(%rsp,%rcx,8), %rcx`
      between the `movzbl bytecode[pc+3], %ecx` and the `rolq %cl, %rdx`.
      The shift count is the literal third operand byte of the opcode,
      masked to 6 bits for 64-bit rotates. For `1a 08 0a 17` the count is
      `0x17 = 23`, not R[7]. Every register-arg ALU op (ADD/SUB/MUL/XOR/AND/OR)
      *does* go through `andl $0xf` + load -- only the shifts are special.

With those two fixes the per-byte transform is invertible, but multiple
inputs collide onto the same low byte at most positions. A greedy
first-match search wedges on a state from which a later cipher byte is
unreachable; a depth-first backtracking search that prefers printable
ASCII walks straight to:

    THEM?!CTF{Entr0py_C0r3_VM_S0_Funny!}

  $ ./solve.py
  THEM?!CTF{Entr0py_C0r3_VM_S0_Funny!}
"""
import argparse
import sys
from pathlib import Path


MASK64 = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C15
INITIAL_STATE = 0xCAFEBABEDEADBEEF
SHIFT = 0x17  # The literal byte from the ROL operand at IMAGE offset 0x78
IMAGE_OFFSET = 0x3060  # File offset of the 284-byte VM IMAGE in entropy_core.exe
IMAGE_SIZE = 284
KEY_OFFSET = 0xE8
KEY_LEN = 16
CT_OFFSET = 0xF8
CT_LEN = 36


def rc4_init(key: bytes) -> list:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S


def rc4_next(S: list, i: int, j: int):
    i = (i + 1) & 0xFF
    j = (j + S[i]) & 0xFF
    S[i], S[j] = S[j], S[i]
    return S[(S[i] + S[j]) & 0xFF], i, j


def rol(v: int, sh: int) -> int:
    sh &= 63
    if sh == 0:
        return v
    return ((v << sh) | (v >> (64 - sh))) & MASK64


def step(R10: int, counter: int, S: list, ri: int, rj: int, guess: int):
    """Apply one iteration of the per-byte hash for input byte `guess`.

    Returns (new_R10, new_S, new_ri, new_rj).
    """
    rc4_byte, ri, rj = rc4_next(S, ri, rj)
    R6 = (counter + 1) & MASK64
    R7 = (rc4_byte * R6) & MASK64
    rep = (guess * 0x0101010101010101) & MASK64
    rt = R10 ^ rep
    rt = (rt + R7) & MASK64
    rt = (rt * GOLDEN) & MASK64
    rt ^= rol(rt, SHIFT)
    return rt, S, ri, rj


def solve(image: bytes) -> bytes:
    key = image[KEY_OFFSET:KEY_OFFSET + KEY_LEN]
    ct = image[CT_OFFSET:CT_OFFSET + CT_LEN]

    S0 = rc4_init(key)

    solution = [None]

    def search(idx: int, R10: int, counter: int, S: list, ri: int, rj: int, path: list) -> bool:
        if idx == CT_LEN:
            solution[0] = bytes(path)
            return True
        target = ct[idx]
        valid = []
        for guess in range(256):
            S_copy = S[:]
            new_R10, _, ri_new, rj_new = step(R10, counter, S_copy, ri, rj, guess)
            if (new_R10 & 0xFF) == target:
                valid.append((guess, new_R10, S_copy, ri_new, rj_new))
        # Prefer printable ASCII first so the first solution looks like a flag.
        valid.sort(key=lambda v: (not (0x20 <= v[0] <= 0x7E), v[0]))
        for guess, new_R10, S_next, ri_next, rj_next in valid:
            path.append(guess)
            if search(idx + 1, new_R10, counter + 1, S_next, ri_next, rj_next, path):
                return True
            path.pop()
        return False

    if not search(0, INITIAL_STATE, 0, S0[:], 0, 0, []):
        raise RuntimeError("no solution found - VM model probably wrong")
    return solution[0]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary", nargs="?", default="handout/entropy_core.exe",
                    type=Path,
                    help="path to entropy_core.exe (default: handout/entropy_core.exe)")
    args = ap.parse_args()

    data = args.binary.read_bytes()
    image = data[IMAGE_OFFSET:IMAGE_OFFSET + IMAGE_SIZE]
    if len(image) != IMAGE_SIZE:
        sys.exit(f"binary too short - need {IMAGE_SIZE} bytes at offset {IMAGE_OFFSET:#x}")

    key = image[KEY_OFFSET:KEY_OFFSET + KEY_LEN]
    sys.stderr.write(f"[+] RC4 key: {key!r} (len={len(key)})\n")
    sys.stderr.write(f"[+] ciphertext: {image[CT_OFFSET:CT_OFFSET + CT_LEN].hex()}\n")

    flag = solve(image)
    print(flag.decode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
