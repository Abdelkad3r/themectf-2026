#!/usr/bin/env python3
"""End-to-end solver for the THEM?! 2026 "Old Cassette" (rev) challenge.

The handout `main.bin` is a 3282-byte CHIP-8 ROM that paints its flag to a
64x32 monochrome screen, character by character. Each character is computed
on the fly from a 16-bit state machine that's iterated for absurd counts
(up to ~10^13 iterations per character).

Naively emulating CHIP-8 to read the screen would take hours. The trick:
the state machine is a pure function of (VA, VB) — 16 bits of state — so
its trajectory from the seed (0xA7, 0xC3) enters a cycle very quickly. In
this ROM the trajectory is **tail=329, cycle=34**, so `state_at(N)` is
constant-time regardless of how huge N gets.

Pipeline:
  1.  Read the state-machine table at 0x800-0x8FF from main.bin.
  2.  Walk the trajectory until we see a repeat → record `traj`, `tail`,
      `cycle`.
  3.  Scan the ROM for the 32 round descriptors. Two flavors:
        - Format A at 0x916..0xB95 (40 bytes each, 16 rounds): explicit
          V9/VC/VD/VE counter (a 32-bit little-endian iter count).
        - Format B at 0xB96..0xDB7 (34 bytes each, 16 rounds): outer
          counter V5=0xFF wraps the 32-bit inner loop → 255*(2**32-1)
          iterations per round.
      Each descriptor also carries:
        - off    — added to a base address picked by VA's low 3 bits
        - xp, yp — sprite coordinates (we only use them to lay out the
                   flag on the conceptual screen).
  4.  Replay rounds: cum += count, lookup `state_at(cum)`, compute
      character V9 = mem[TBL[VA&7]+off] ^ VA ^ VB, place at (xp, yp).
  5.  Read the resulting screen row by row.

The destructive write `mem[addr] = VB` after each lookup happens but
never lands on an address used by a later round in this ROM — so we
*could* skip it; we still perform it for fidelity.
"""
import argparse
import sys
from pathlib import Path


TABLE_BASE_BY_LOWBITS = {
    0: 0x400, 1: 0x460, 2: 0x4C0, 3: 0x520,
    4: 0x600, 5: 0x660, 6: 0x6C0, 7: 0x720,
}
TAIL_XOR = {0x00: 0xA9, 0x40: 0x5C, 0x80: 0xD3, 0xC0: 0x76}


def load_mem(rom_path: Path) -> bytearray:
    rom = rom_path.read_bytes()
    mem = bytearray(0x1000)
    mem[0x200:0x200 + len(rom)] = rom
    return mem


def encoder_step(va: int, vb: int, mem: bytearray) -> tuple[int, int]:
    v0 = mem[0x800 + vb] ^ vb ^ TAIL_XOR[vb & 0xC0]
    s = vb + v0
    vb_new = s & 0xFF
    vf = 1 if s > 0xFF else 0
    va_new = (va + vf) & 0xFF
    val = ((va << 8) | vb)
    val = ((val << 5) | (val >> 11)) & 0xFFFF
    va_new ^= (val >> 8)
    vb_new ^= val & 0xFF
    return va_new, vb_new


def build_trajectory(mem: bytearray, seed=(0xA7, 0xC3)):
    state = seed
    seen = {state: 0}
    traj = [state]
    while True:
        state = encoder_step(*state, mem)
        if state in seen:
            tail = seen[state]
            cycle = len(traj) - tail
            return traj, tail, cycle
        seen[state] = len(traj)
        traj.append(state)


def state_at(N: int, traj, tail, cycle):
    if N < len(traj):
        return traj[N]
    return traj[tail + (N - tail) % cycle]


def extract_rounds(mem: bytearray):
    """Return list[(iter_count, table_offset, xp, yp)]."""
    rounds = []

    # Format A — 16 fixed-count rounds at 0x916, 40 bytes each
    for i in range(16):
        base = 0x916 + i * 40
        v9, vc = mem[base + 1], mem[base + 3]
        vd, ve = mem[base + 5], mem[base + 7]
        count = v9 | (vc << 8) | (vd << 16) | (ve << 24)
        off, xp, yp = mem[base + 0x13], mem[base + 0x23], mem[base + 0x25]
        rounds.append((count, off, xp, yp))

    # Format B — V5=0xFF wrapper, 34 bytes each, scan 0xB96..0xDB8
    count_b = 0xFF * (2 ** 32 - 1)
    a = 0xB96
    while a < 0xDB8 - 0x22:
        if mem[a] == 0x65 and mem[a + 1] == 0xFF \
                and mem[a + 2] == 0x22 and mem[a + 3] == 0xAC:
            off, xp, yp = mem[a + 0x0D], mem[a + 0x1D], mem[a + 0x1F]
            rounds.append((count_b, off, xp, yp))
            a += 0x22
        else:
            a += 2
    return rounds


def replay(mem: bytearray, rounds, traj, tail, cycle):
    cum = 0
    placed = []  # (yp, xp, ch)
    for count, off, xp, yp in rounds:
        cum += count
        va, vb = state_at(cum, traj, tail, cycle)
        addr = TABLE_BASE_BY_LOWBITS[va & 7] + off
        byte = mem[addr]
        v9 = byte ^ va ^ vb
        mem[addr] = vb           # destructive write (faithful, but not load-bearing)
        placed.append((yp, xp, chr(v9) if 0x20 <= v9 < 0x7F else "?"))
    return placed


def render(placed):
    placed.sort()
    rows = []
    cur_y, line = None, ""
    for y, x, ch in placed:
        if cur_y is None:
            cur_y = y
        if y != cur_y:
            rows.append(line)
            line = ""
            cur_y = y
        line += ch
    rows.append(line)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("rom", nargs="?", default="handout/main.bin", type=Path,
                    help="path to main.bin (default: handout/main.bin)")
    args = ap.parse_args()

    mem = load_mem(args.rom)
    traj, tail, cycle = build_trajectory(mem)
    sys.stderr.write(f"[+] trajectory: tail={tail}, cycle={cycle}, total={len(traj)}\n")

    rounds = extract_rounds(mem)
    sys.stderr.write(f"[+] rounds: {len(rounds)}\n")

    placed = replay(mem, rounds, traj, tail, cycle)
    rows = render(placed)

    sys.stderr.write("\n[+] screen layout:\n")
    for r in rows:
        sys.stderr.write(f"    {r}\n")

    print("".join(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
