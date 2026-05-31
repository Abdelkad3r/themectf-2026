# Old Cassette (rev)

| Field    | Value                                                     |
| -------- | --------------------------------------------------------- |
| Category | rev                                                       |
| Target   | `main.bin` — 3282-byte CHIP-8 ROM                         |
| Flag     | `THEM?!CTF{0LD_T4P3_N3V3R_D1E5K7}`                        |

## Description

A single binary, no remote, no source. The brief is just *"old cassette"*.
File starts with `00E0 1280` which is the classic CHIP-8 opcode pair
**CLS; JP 0x280** — i.e. clear screen and jump into a routine at 0x280
inside the standard CHIP-8 memory map (ROM loads at 0x200).

There's no input prompt; no flag string sitting in plaintext. The ROM
*paints the flag onto a 64×32 monochrome display* using a state machine
that's iterated for absurd counts — up to ~10¹³ encoder steps per
character. Naively emulating the ROM would take hours. The whole trick is
that the state machine is a pure function on 16 bits of state, so its
trajectory enters a short cycle almost immediately and `state_at(N)` is
constant-time once you know the cycle.

## TL;DR

1. The state machine at `0x2C0` is a deterministic update on `(VA, VB)`,
   seeded with `(0xA7, 0xC3)`. Build the trajectory until it loops:
   **tail = 329, cycle = 34**.
2. The main routine at `0x900` runs 32 *rounds*. Each round iterates the
   encoder a hard-coded number of times, then prints **one character** of
   the flag at a hard-coded screen position.
   - Rounds 0–15 use explicit counts `1, 4, 16, …, 4¹⁵` packed into
     `V9/VC/VD/VE` (a 32-bit little-endian counter).
   - Rounds 16–31 use the wrapper at `0x2AC` with `V5=0xFF`, which fires
     the inner 32-bit loop 255 times — **255 × (2³² − 1) ≈ 2⁴⁰ encoder
     steps per round**.
3. Each round's character is
   `chr = mem[TBL[VA & 7] + off] ^ VA ^ VB`,
   where `TBL` is a 9-byte dispatch table at `0x322` and `off` is encoded
   into the round itself.
4. Replay all 32 rounds with cumulative iteration counting, sort the
   characters by `(yp, xp)`, read the screen:

```
THEM?!CTF{
0LD_T4P3_N
3V3R_D1E5K
7}
```

→ `THEM?!CTF{0LD_T4P3_N3V3R_D1E5K7}`. Leet decode: *"old tape never dies,
K7"* — French slang **K7** ("ka-sept") meaning **cassette**. The flag
*is* the challenge title.

## Recon

### CHIP-8 layout

Standard CHIP-8 maps ROM at `0x200`. Reading the first two opcodes:

```
0x200: 00 E0     CLS
0x202: 12 80     JP 0x280
0x204..0x27F:    0xA6 repeated  (dead bytes, never executed)
0x280: 19 00     JP 0x900        ← real entry
```

The dead bytes at `0x204..0x27F` decode as `A6A6` (LD I, 0x6A6) repeated
60 times — never reached, presumably padding/decoy.

### The state machine (0x2C0)

Disassembling the subroutine at `0x2C0`:

```
; one encoder step:  (VA, VB) → (VA', VB')
0x2C0: LD V2, VA            ; save the inputs (V2,V3) = (VA,VB)
0x2C2: LD V3, VB
0x2C4: LD I, 0x800
0x2C6: ADD I, VB            ; I = 0x800 + VB
0x2C8: LD V0, [I]           ; v0 = mem[0x800 + VB]
0x2CA: XOR V0, VB           ; v0 ^= VB
0x2CC: LD V8, VB            ; switch on (VB & 0xC0):
0x2CE: LD V7, 0xC0          ;   0x00 → v0 ^= 0xA9
0x2D0: AND V8, V7           ;   0x40 → v0 ^= 0x5C
0x2D2..0x2FA: dispatch       ;   0x80 → v0 ^= 0xD3
                            ;   0xC0 → v0 ^= 0x76
0x2FC: ADD VB, V0           ; VB += v0   (carry → VF)
0x2FE: ADD VA, VF           ; VA += VF
0x300: LD V8, 5             ; 16-bit ROL of saved (V2||V3) by 5
0x302..0x312: loop V8 times: V3 *= 2 (carry V6); V2 *= 2 (carry V7);
                            V2 |= V6; V3 |= V7
0x314: XOR VA, V2           ; mix the rotated copy into (VA, VB)
0x316: XOR VB, V3
0x318..0x31E: store V0,V1 at 0x58B (housekeeping)
0x320: RET
```

In Python:

```python
def encoder_step(va, vb):
    v0  = mem[0x800 + vb] ^ vb ^ {0x00:0xA9, 0x40:0x5C,
                                  0x80:0xD3, 0xC0:0x76}[vb & 0xC0]
    s   = vb + v0
    vb_ = s & 0xFF
    vf  = 1 if s > 0xFF else 0
    va_ = (va + vf) & 0xFF
    val = ((va << 8) | vb)
    val = ((val << 5) | (val >> 11)) & 0xFFFF
    return (va_ ^ (val >> 8), vb_ ^ (val & 0xFF))
```

The reference table at `0x800..0x8FF` is read-only — no round writes to
that range — so the encoder is a **pure function of (VA, VB)**, a 16-bit
state. Trajectory from the seed `(0xA7, 0xC3)`:

```
tail = 329, cycle = 34, total reachable states = 363
```

So for *any* iteration count `N`:

```python
def state_at(N):
    if N < len(traj): return traj[N]
    return traj[tail + (N - tail) % cycle]
```

`state_at(10**13)` is one modulo and an array index.

### The driver loop at 0x900

Disassembling `0x900..0xA00` reveals a repeating block — 40 bytes per
iteration, 16 iterations:

```
LD V9, count_lo                 \
LD VC, count_b1                  >  load 32-bit counter into V9/VC/VD/VE
LD VD, count_b2                  /
LD VE, count_b3                 /
CALL 0x282                      ; run encoder `counter` times
LD V0, VA                       \
LD V1, 0x07                      >  V0 = VA & 7
AND V0, V1                      /
CALL 0x322                      ; I = TBL[V0]  (dispatch table)
LD V1, off                      \
ADD I, V1                        >  fetch byte, derive character
LD V0, [I]                      /
LD V9, V0
XOR V9, VA                      ; V9 = mem[I] ^ VA ^ VB
XOR V9, VB
LD V0, VB
LD [I], V0                      ; destructive write (mem[I] = VB)
LD V2, xp                       \
LD V3, yp                        >  draw V9 at (xp, yp)
CALL 0xDD2                      /
```

Counter values across the 16 rounds:

```
1, 4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576,
4194304, 16777216, 67108864, 268435456, 1073741824
```

— a `4ⁿ` series, packed neatly into 4 bytes. After round 15 the counter
needs ≥ 33 bits, which is where the second pattern at `0xB96` comes in.

The dispatch at `0x322` is just a switch on `V0 ∈ 0..7`:

```
TBL = {0:0x400, 1:0x460, 2:0x4C0, 3:0x520,
       4:0x600, 5:0x660, 6:0x6C0, 7:0x720}
```

### Rounds 16–31: the bigger-counter wrapper

From `0xB96` onward the per-round template changes (34 bytes instead of
40):

```
LD V5, 0xFF
CALL 0x2AC                      ; outer wrapper
...
```

The wrapper at `0x2AC`:

```
0x2AC: SE V5, 0
0x2AE: JP 0x2B2
0x2B0: RET
0x2B2: LD V9, 0xFF
0x2B4: LD VC, 0xFF
0x2B6: LD VD, 0xFF
0x2B8: LD VE, 0xFF
0x2BA: CALL 0x282               ; inner 32-bit loop (2^32 - 1 iters)
0x2BC: ADD V5, 0xFF             ; V5--
0x2BE: JP 0x2AC
```

So each round of the second batch runs **255 × (2³² − 1) ≈ 1.095 × 10¹²**
encoder steps. Cumulative encoder iterations by round 31:

```
Σ counts ≈ 1.75 × 10¹³
```

Un-emulatable directly. But `state_at(N)` from the cycle table handles it
in O(1).

## Exploit

The solver, in three parts:

```python
# 1) build the cycle
traj, tail, cycle = build_trajectory(mem, seed=(0xA7, 0xC3))

# 2) scan rounds from the ROM (two templates, 16+16)
rounds = extract_rounds(mem)

# 3) replay
cum = 0
placed = []
for count, off, xp, yp in rounds:
    cum += count
    va, vb = state_at(cum, traj, tail, cycle)
    addr   = TBL[va & 7] + off
    ch     = chr(mem[addr] ^ va ^ vb)
    mem[addr] = vb                  # faithful destructive write
    placed.append((yp, xp, ch))

# sort by (yp, xp), render rows → "THEM?!CTF{0LD_T4P3_N3V3R_D1E5K7}"
```

Worth confirming the destructive writes never collide with later round
addresses (they don't, in this ROM) — otherwise the trajectory you
computed offline could disagree with the in-emulator state. Quick check:

```python
addrs = []
cum = 0
for count, off, xp, yp in rounds:
    cum += count
    va, vb = state_at(cum, traj, tail, cycle)
    addrs.append(TBL[va & 7] + off)
assert len(addrs) == len(set(addrs))     # no collisions
```

End-to-end run:

```
$ ./solve.py
[+] trajectory: tail=329, cycle=34, total=363
[+] rounds: 32
[+] screen layout:
    THEM?!CTF{
    0LD_T4P3_N
    3V3R_D1E5K
    7}
THEM?!CTF{0LD_T4P3_N3V3R_D1E5K7}
```

## Flag

```
THEM?!CTF{0LD_T4P3_N3V3R_D1E5K7}
```

**Decoded.** Leet: `OLD TAPE NEVER DIES K7`. The trailing **K7** is
French slang — "ka-sept" — for *cassette*. The flag is the title.

## Defender notes

* **Iteration counts are theater.** The headline scariness of the ROM —
  10¹³ encoder steps per character — is meaningless against an attacker
  who notices the state machine has a 16-bit state. Pure functions on
  small state spaces always cycle quickly; brute-forcing the cycle once
  beats any practical iteration count. If you want the iteration count
  itself to matter, the state has to be *not* small (think 256-bit), or
  the loop has to depend on output it can't predict (e.g. mix in `DT` or
  a key press, which CHIP-8 does support).
* **Self-modifying tables that don't actually self-modify.** The ROM
  writes `mem[TBL[VA&7] + off] = VB` after each character lookup,
  presumably to confuse anyone running it twice. In practice no address
  is touched by more than one round, so the writes are observable noise,
  not a defense. If you want to force in-order emulation, *do* have the
  later rounds depend on the writes — overlap addresses so that an
  attacker who skips ahead gets the wrong byte.
* **Drawing the flag is leakier than printing it.** Because the
  flag-painting routine sets each glyph at a fixed `(xp, yp)`, the
  cleartext reaches a known display address — you don't even need to
  reverse the dispatch to figure out what's printed, just snapshot the
  framebuffer after `mainLoop` returns. A more robust hider would route
  the same characters through a comparison-only path that never appears
  on screen.
* **CHIP-8 is a fun target for this kind of puzzle.** The instruction
  set is tiny (35 opcodes), the memory map is 4 KiB, and `(VA, VB)` is
  literally 16 bits. There's nowhere for a secret to hide that can't be
  found by walking the instruction graph. For obfuscation that *survives*
  reverse engineering you need either real cryptographic primitives or
  enough state to make brute-forcing the cycle expensive — neither of
  which CHIP-8 affords.

## Files

* [`solve.py`](./solve.py) — argparse-driven solver. Builds the
  trajectory once, scans the ROM for both round formats, replays the 32
  rounds, reads the screen.
* [`handout/main.bin`](./handout/main.bin) — original CHIP-8 ROM, 3282
  bytes.
