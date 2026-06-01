#!/usr/bin/env python3
"""End-to-end solver for the THEM?! CTF 2026 "1983" (rev) challenge.

`1983.exe` is a 22.5 KB PE32+ x86-64 console crackme (MinGW GCC 15.2.0)
that asks for a 113-byte input at the `flag> ` prompt and compares it
against an internally-computed expected buffer via a SIMD XOR-and-fold.

The computation of the expected buffer is the entire challenge. main
runs a control-flow-flattened state-machine VM:

  * A 16-byte working state lives at `[rsp+0xa8]`, seeded from two
    `.rdata` constants at `0x140005770` / `0x140005778`
    (`07 38 69 9a cb fc 2d 5e | 00 01 02 03 04 05 06 07`).
  * A 36-entry jump table at `0x140005018` dispatches the next handler.
    Only 15 opcodes route to "real" handlers; the rest funnel to a
    `WRONG-EXIT` sink (textbook CFG-flattening junk slots).
  * Every dispatch *mutates state[esi] / state[state[14]] /
    state[state[15]]* using
        ((ecx*2) XOR r11 XOR state[state[8]] XOR opcode) & 3
    so the same code path produces different effects in different
    iterations -- the flag literally calls this out:
    "...MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG..."
  * Each iteration eventually writes ONE byte of the expected flag into
    the 113-byte buffer at `[rsp+0xbf]`.

Static analysis is hostile. Dynamic is trivial: load the PE into
Unicorn, map every section at its preferred VA, set up the same stack
layout main does, jump straight to the VM dispatcher entry, and hook
writes to the expected-buffer range. When RIP reaches the `flag> `
prompt the buffer is fully populated -- read 113 bytes off the stack
and you have the flag.

  $ python3 -m pip install unicorn
  $ ./solve.py
  THEM?!CTF{R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL}
"""
import argparse
import struct
import sys
from pathlib import Path

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UC_HOOK_CODE
    from unicorn.x86_const import (
        UC_X86_REG_RSP, UC_X86_REG_R11, UC_X86_REG_R12,
        UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RIP,
    )
except ImportError:
    print("requires unicorn  --  pip install unicorn", file=sys.stderr)
    sys.exit(1)


IMG_BASE = 0x140000000
STACK_BASE = 0x10000000
STACK_SIZE = 0x100000

VM_ENTRY  = 0x140002ac0   # right after the CRT init call in main
PROMPT_RIP = 0x140002b80   # `leaq "flag> ", %rcx` -> VM has finished
EXPECTED_OFFSET = 0xbf     # the 113-byte buffer lives at rsp+0xbf
EXPECTED_LEN    = 113


def parse_pe_sections(data: bytes):
    """Yield (name, vaddr, file_off, raw_size) for each PE section."""
    e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[e_lfanew:e_lfanew + 4] == b"PE\0\0"
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    opthdr_size = struct.unpack_from("<H", data, coff + 16)[0]
    sec_off = coff + 20 + opthdr_size
    for i in range(nsec):
        h = data[sec_off + i * 40:sec_off + (i + 1) * 40]
        name = h[:8].rstrip(b"\0").decode("latin-1")
        vsize, vaddr, raw_size, raw_off = struct.unpack_from("<IIII", h, 8)
        yield name, vaddr, raw_off, raw_size


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary", nargs="?", default="handout/1983.exe",
                    type=Path)
    args = ap.parse_args()

    data = args.binary.read_bytes()

    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # Map the PE image: one read-write-exec region big enough for every
    # section, then drop each raw section at its vaddr inside it.
    image_size = 0x20000
    mu.mem_map(IMG_BASE, image_size, UC_PROT_ALL)
    for name, vaddr, raw_off, raw_size in parse_pe_sections(data):
        if raw_size == 0:
            continue
        mu.mem_write(IMG_BASE + vaddr, data[raw_off:raw_off + raw_size])
        sys.stderr.write(f"[+] loaded {name:8s} at {IMG_BASE + vaddr:#x} size {raw_size:#x}\n")

    # Stack
    mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    rsp = STACK_BASE + STACK_SIZE - 0x1000
    # Push a fake return address so main can "return" without crashing
    # if it ever does (it doesn't in our window).
    mu.mem_write(rsp, struct.pack("<Q", 0xdead0000))

    # Replicate main's prologue state setup so the VM dispatcher runs in
    # the same conditions it would in the real binary:
    #   * zero [rsp+0xb8 ... rsp+0x130) (0x78 bytes)
    #   * [rsp+0xb0] = qword @0x140005770
    #   * [rsp+0xa8] = qword @0x140005778
    #   * r12=0 r11=1 rdx=4 rcx=0x13579bd
    #   * r13 = rsp+0x130, r15 = 0x140005018 (jump table base),
    #     r14 = 0x140005580 (instruction tape)
    mu.mem_write(rsp + 0xb8, b"\0" * 0x78)
    mu.mem_write(rsp + 0xb0, bytes(mu.mem_read(0x140005770, 8)))
    mu.mem_write(rsp + 0xa8, bytes(mu.mem_read(0x140005778, 8)))

    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_R12, 0)
    mu.reg_write(UC_X86_REG_R11, 1)
    mu.reg_write(UC_X86_REG_RDX, 4)
    mu.reg_write(UC_X86_REG_RCX, 0x13579bd)
    mu.reg_write(UC_X86_REG_R13, rsp + 0x130)
    mu.reg_write(UC_X86_REG_R14, 0x140005580)
    mu.reg_write(UC_X86_REG_R15, 0x140005018)

    # Track writes to the expected-flag buffer at [rsp+0xbf .. rsp+0x130).
    buf_start = rsp + EXPECTED_OFFSET
    buf_end   = buf_start + EXPECTED_LEN
    captured = [None] * EXPECTED_LEN

    from unicorn import UC_HOOK_MEM_WRITE
    def write_hook(uc, access, addr, size, value, user_data):
        for off in range(size):
            a = addr + off
            if buf_start <= a < buf_end:
                captured[a - buf_start] = (value >> (8 * off)) & 0xff
    mu.hook_add(UC_HOOK_MEM_WRITE, write_hook)

    # Stop the second the VM cycle terminates and main is about to load
    # the "flag> " string into rcx -- by that point the buffer is the
    # expected input verbatim.
    sys.stderr.write(f"[+] emulating {VM_ENTRY:#x} -> {PROMPT_RIP:#x}\n")
    try:
        mu.emu_start(VM_ENTRY, PROMPT_RIP, timeout=10_000_000, count=2_000_000)
    except Exception as e:
        sys.stderr.write(f"[!] emulation stopped: {e}\n")

    # Prefer the bytes that actually landed in the buffer; fall back to
    # whatever Unicorn left there if a few offsets missed the hook.
    raw = bytes(mu.mem_read(buf_start, EXPECTED_LEN))
    out = bytes((captured[i] if captured[i] is not None else raw[i])
                for i in range(EXPECTED_LEN))
    print(out.decode("latin-1"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
