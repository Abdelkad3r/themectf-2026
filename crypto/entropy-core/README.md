# Entropy Core (crypto)

| Field    | Value                                                            |
| -------- | ---------------------------------------------------------------- |
| Category | crypto                                                           |
| Target   | `entropy_core.exe` — 134 KB, PE32+ console x86-64 (MinGW GCC 15.1.0) |
| Flag     | `THEM?!CTF{Entr0py_C0r3_VM_S0_Funny!}`                           |

## Description

> `[Entropy Core v1] quantum lattice primed -- insert star key:`

A single-prompt crackme. Type 36 bytes; receive `starlight conduit aligned. access accepted.` or
`CRITICAL: warp drift -- reactor SCRAM.` The visible interface hides a
hand-rolled register VM whose entire program is a 284-byte bytecode blob
embedded in `.rdata`. The flag is the 36-byte input that the VM is
willing to accept.

## TL;DR

* `entropy_core.exe` is a thin C wrapper around a 16-register, 64-bit
  bytecode VM. 30 opcodes are reachable through a `cmpb $0x61` jump table
  at `0x1400050c0`.
* The VM's 284-byte program (at `.rdata` VA `0x140005260`) reads 36
  characters, runs each through a per-byte hash that mixes the input into
  a 64-bit state `R10`, and compares its low byte against a 36-byte
  ciphertext stored at the tail of the program.
* The per-byte transform is invertible **byte by byte once you understand
  it**, but only after two static-analysis traps are dealt with — the
  apparent 232-byte RC4 key is a fake-out (real key is 16 bytes), and the
  shift in `ROL`/`SHL`/`SHR`/`ROR` is *the literal third operand byte*,
  not the value of a register.
* With both fixes, position 0 has many input bytes that all hit the
  target cipher byte; a greedy first-match search gets stuck after ~9
  iterations. A depth-first backtracking search that prefers printable
  ASCII walks straight to the flag.

```
$ ./solve.py
[+] RC4 key: b'EntropyCoreV1!\x00\x00' (len=16)
[+] ciphertext: be8b850316a36e7481bb764a3027a86d11be9866e005f1a4bca705d3139f119170f5f46d
THEM?!CTF{Entr0py_C0r3_VM_S0_Funny!}
```

## Recon

### Step 1 — strings and shape

```
$ file entropy_core.exe
entropy_core.exe: PE32+ executable (console) x86-64, for MS Windows

$ strings entropy_core.exe | grep -iE 'entropy|access|warp|core'
[Entropy Core v1] quantum lattice primed -- insert star key:
[Entropy Core] starlight conduit aligned. access accepted.
[Entropy Core] CRITICAL: warp drift -- reactor SCRAM.
EntropyCoreV1!
```

The token `EntropyCoreV1!` is suggestive — it's the only non-message
string in the binary. Save it for later.

### Step 2 — find main, find the dispatch

`objdump -d` shows main at `0x140002880`. After the usual prologue it:

1. `memset(rbp, 0, 0x10190)` — zero a 64 KB buffer at `rsp+0x20`.
2. `rep movsq` 35 qwords + a stray `movl` (280 + 4 = **284 bytes**) from
   `0x140005260` to `rsp+0xa0`. That's the **program image**.
3. Falls into a dispatch loop at `0x140002990`:

```nasm
movzwl  bx, eax           ; pc (16-bit)
leal    1(rbx), edx       ; pc+1 (operand offset)
movzbl  0xa0(rsp,rax), eax ; opcode = bytecode[pc]
cmpb    $0x61, al         ; opcodes are 0x00..0x61
ja      default
movslq  (rsi,rax,4), rax  ; rsi = 0x1400050c0  (jump table base)
addq    rsi, rax
jmpq    *rax              ; handler
```

The jump table is a 98-entry array of signed 32-bit relative offsets
(target = base + offset). Decoding it gives 30 distinct handlers — the
30 active opcodes of the VM. Everything else falls to a `default`
handler at `0x1400029b0` that prints success or failure based on the
status word at `rsp+0x101ac` and exits.

### Step 3 — recover the opcode table

Reading each handler in turn yields:

| Opcode | Bytes | Name | Semantics |
|:------:|:-----:|:-----|:----------|
| 0x00 | 1 | HALT / default | check status, print success/failure, exit |
| 0x01 | 1 | END | same as 0x00 |
| 0x02 | 1 | NOP1 | pc += 1 |
| 0x10 | 10 | `LD reg, imm64` | `R[byte1&0xf] = imm64` (little-endian) |
| 0x11 | 3 | `MOV dst, src` | `R[dst] = R[src]` |
| 0x12 | 4 | `ADD dst, a, b` | `R[dst] = R[a] + R[b]` |
| 0x13 | 4 | `SUB dst, a, b` | `R[dst] = R[b] - R[a]` *(see "traps" below)* |
| 0x14 | 4 | `MUL dst, a, b` | `R[dst] = R[a] * R[b]` (mod 2^64) |
| 0x15 | 4 | `XOR dst, a, b` | `R[dst] = R[a] ^ R[b]` |
| 0x16 | 4 | `AND dst, a, b` | `R[dst] = R[a] & R[b]` |
| 0x17 | 4 | `OR  dst, a, b` | `R[dst] = R[a] \| R[b]` |
| 0x18 | 4 | `SHL dst, a, k` | `R[dst] = R[a] << (k & 63)` *(k is a literal byte, not a reg!)* |
| 0x19 | 4 | `SHR dst, a, k` | `R[dst] = R[a] >> (k & 63)` *(same)* |
| 0x1A | 4 | `ROL dst, a, k` | `R[dst] = rol(R[a], k & 63)`     *(same)* |
| 0x1B | 4 | `ROR dst, a, k` | `R[dst] = ror(R[a], k & 63)`     *(same)* |
| 0x20 | 5 | `LDB dst, idx, u16` | `R[dst] = bytecode[u16 + R[idx]]` (zero-extend) |
| 0x21 | 5 | `LDQ dst, idx, u16` | `R[dst] = u64 at bytecode[u16 + R[idx]]` |
| 0x22 | 5 | `STB idx, src, u16` | `bytecode[u16 + R[idx]] = R[src] & 0xff` |
| 0x23 | 5 | `STQ idx, src, u16` | `u64 at bytecode[u16 + R[idx]] = R[src]` |
| 0x30 | 2 | `PUSH reg` | `sp -= 8; mem[sp] = R[reg]` |
| 0x31 | 2 | `POP  reg` | `R[reg] = mem[sp]; sp += 8` |
| 0x40 | 3 | `JMP u16` | `pc = u16` |
| 0x41 | 4 | `JZ  reg, u16` | `if R[reg] == 0: pc = u16` |
| 0x42 | 4 | `JNZ reg, u16` | `if R[reg] != 0: pc = u16` |
| 0x43 | 5 | `JEQ r1, r2, u16` | `if R[r1] == R[r2]: pc = u16` |
| 0x44 | 5 | `JNE r1, r2, u16` | `if R[r1] != R[r2]: pc = u16` |
| 0x45 | 3 | `CALL u16` | push pc+3, pc = u16 |
| 0x46 | 1 | `RET` | pop, pc = low 16 bits of popped value |
| 0x50 | 4 | `RC4_KSA reg, u16` | init S-box with key bytes (see "Trap 1") |
| 0x51 | 2 | `RC4_NEXT reg` | `R[reg] = next RC4 PRGA byte` |
| 0x60 | 2 | `GETCHAR reg` | `R[reg] = getchar()` (`-1` on EOF) |
| 0x61 | 2 | `PUTCHAR reg` | `putchar(R[reg] & 0xff)` |

The opcode width is encoded in the handler itself (the `addl $0xN, %ebx`
that advances PC). Anything outside this table goes to default (HALT).

### Step 4 — disassemble the program

Hand-walking the 284-byte image and matching opcode boundaries gives:

```
0x00  10 00  e8 00 00 00 00 00 00 00      ; LD  R0,  0xe8           ; "key length" (sort of - see Trap 1)
0x0a  50 00  10 00                        ; RC4_KSA R0, 0x10        ; key_addr = 0x10
0x0e  10 0a  ef be ad de be ba fe ca      ; LD  R10, 0xcafebabedeadbeef
0x18  10 0b  00 00 00 00 00 00 00 00      ; LD  R11, 0              ; counter
0x22  10 0c  24 00 00 00 00 00 00 00      ; LD  R12, 36             ; loop bound
0x2c  10 0d  f8 00 00 00 00 00 00 00      ; LD  R13, 0xf8           ; ciphertext pointer

0x36  43 0b 0c  aa 00                     ; LOOP_TOP: if R11==R12 jmp 0xaa (SUCCESS)
0x3b  60 01                                ;   R1  = getchar()
0x3d  51 02                                ;   R2  = RC4_NEXT()
0x3f  10 03  01 01 01 01 01 01 01 01      ;   R3  = 0x0101010101010101
0x49  14 04 01 03                          ;   R4  = R1 * R3        ; replicate input byte across 8 bytes
0x4d  15 0a 0a 04                          ;   R10 = R10 ^ R4
0x51  10 05  01 00 00 00 00 00 00 00      ;   R5  = 1
0x5b  12 06 0b 05                          ;   R6  = R11 + 1
0x5f  14 07 02 06                          ;   R7  = R2 * R6        ; rc4_byte * counter
0x63  12 0a 0a 07                          ;   R10 = R10 + R7
0x67  10 03  15 7c 4a 7f b9 79 37 9e      ;   R3  = 0x9e3779b97f4a7c15  ; golden ratio
0x71  14 0a 0a 03                          ;   R10 = R10 * R3
0x75  1a 08 0a 17                          ;   R8  = ROL(R10, 0x17) ; *** Trap 2 ***
0x79  15 0a 0a 08                          ;   R10 = R10 ^ R8
0x7d  20 03 0d  00 00                     ;   R3  = mem[0 + R13]   ; ciphertext byte
0x82  10 05  ff 00 00 00 00 00 00 00      ;   R5  = 0xff
0x8c  16 09 0a 05                          ;   R9  = R10 & R5       ; low byte of state
0x90  44 09 03  cf 00                     ;   if R9 != R3 jmp 0xcf (FAIL path)
0x95  10 05  01 00 00 00 00 00 00 00      ;   R5  = 1
0x9f  12 0d 0d 05                          ;   R13++                ; next ciphertext byte
0xa3  12 0b 0b 05                          ;   R11++                ; counter++
0xa7  40 36 00                              ;   jmp LOOP_TOP

0xaa  …LD R1,'O'; PUTCHAR; LD R1,'K'; PUTCHAR; LD R1,'\n'; PUTCHAR; …
0xce  …(falls through into the FAIL block at 0xcf)…
0xcf  10 01 58 …                           ; LD R1, 'X' ; PUTCHAR ; LD R1, '\n' ; PUTCHAR ; HALT
0xe7  00                                   ; HALT marker
0xe8  45 6e 74 72 6f 70 79 43 6f 72 65 56 31 21 00 00   ; "EntropyCoreV1!\0\0"  ← the real RC4 key
0xf8  be 8b 85 03 16 a3 6e 74 …            ; 36-byte ciphertext
```

Reading this in plain English: for each input byte, mix it into a 64-bit
state via a small RC4-keyed avalanche and demand that its low byte equals
the next ciphertext byte. If all 36 match, jump to the success block;
otherwise to the failure block.

### Trap 1 — the apparent 232-byte RC4 key

The first instruction is `LD R0, 0xe8` (= 232), and the RC4 KSA call is
`RC4_KSA R0, 0x10` — which on a naïve read means "init a key schedule
with 232 bytes starting at bytecode offset 0x10". That stretch covers
almost the entire program, including the bytes that have already been
disassembled as instructions. It is the wrong reading.

The KSA inner loop looks like this:

```nasm
0x140002bf0:
    movl    %ecx, %eax           ; i
    movzbl  (%r8), %r10d          ; key_byte = S[i]   (r8 walks the S-box)
    addl    $0x1, %ecx
    addq    $0x1, %r8
    cltd
    idivl   %ebx                  ; edx = i % 0x10    (ebx = u16 operand of opcode)
    addl    %r11d, %edx           ; edx += R0 = 0xe8
    movzwl  %dx, %edx
    movzbl  0xa0(%rsp,%rdx), %eax ; eax = bytecode[(i % 16) + 0xe8]
    addl    %r10d, %eax
    addl    %eax, %r9d            ; j_accum = (j_accum + S[i] + key_byte) & 0xff
    ...
```

The crucial line is `idivl %ebx` immediately followed by `addl %r11d, %edx`.
The divisor is the u16 operand (`0x10`); the addend is `R[R0_reg] = 232`.
So the per-iteration key-byte address is `(i mod 16) + 0xe8`, **not**
`(i mod 232) + 0x10`. The RC4 key is the 16 bytes at IMAGE[0xe8..0xf8] —
`"EntropyCoreV1!\0\0"`. The `LD R0, 0xe8` looks like a length but it is
actually the *offset* of the real key.

This is a clean misdirection — the `R0=232 / KSA arg=0x10` pair fits the
shape of a standard "key length, key pointer" call, and `IMAGE[0x10..0xf8]`
is exactly 232 bytes long. It just isn't what the math says.

### Trap 2 — shift counts are operands, not registers

Every other 4-byte ALU opcode (ADD, SUB, MUL, XOR, AND, OR, MOV) does
the same little ritual in its handler:

```nasm
movzbl  bytecode[pc+3], %ecx     ; ecx = third operand byte
andl    $0xf, %ecx                ; -> low nibble (register index)
...
addq    0x20(%rsp,%rcx,8), %rdx  ; -> dereference R[ecx]
```

The shifts (`SHL`/`SHR`/`ROL`/`ROR`) skip the second step:

```nasm
movzbl  bytecode[pc+3], %ecx     ; ecx = third operand byte
                                  ; NO `andl $0xf` AND NO register load
rolq    %cl, %rdx                ; cl is the LITERAL byte, masked to 6 bits by the CPU
```

So in `1a 08 0a 17`, the shift count is `0x17 = 23`, not `R[7]`. Any
emulator that treats all 4-byte opcodes the same way gets a wrong shift
on every rotate — and on this specific bytecode, that turns the avalanche
non-surjective on every iteration. `ciphertext[0] = 0xbe` becomes
unreachable for every choice of input byte, so a "no input matches"
failure pins the trap precisely.

The tell in the handler is the *absence* of `andl $0xf, %ecx` followed
by `movq 0x20(%rsp,%rcx,8), …` — every other ALU handler has it, the
four shifts do not. Once you treat the third operand as a literal, every
cipher byte is in range and the per-byte transform's image size jumps
from ~142 to ~256.

### Step 5 — write the per-byte hash, search over inputs

For each position i (0..35):

```
R7      = RC4_next_byte * (i + 1)                # depends only on RC4 state and i
state0  = R10                                    # state from previous iteration
guess  → state' = ((state0 ^ (guess * 0x0101…01)) + R7) * GOLDEN
        state' ^= ROL(state', 23)
require state' & 0xff == ciphertext[i]
```

Because the low-byte map is many-to-one (typically 5–20 valid `guess`
values per position), a greedy left-to-right search picks the wrong
`guess` early and gets wedged later. Depth-first backtracking with a
preference for printable ASCII walks straight through. With 36 positions
and only a handful of branches per node, this terminates in milliseconds:

```python
def search(idx, R10, counter, S, ri, rj, path):
    if idx == 36:
        return path
    target = ct[idx]
    for guess in printable_first(range(256)):
        S2 = S[:]; rc4_byte, ri2, rj2 = rc4_next(S2, ri, rj)
        R7 = (rc4_byte * (counter + 1)) & MASK64
        rt = R10 ^ (guess * 0x0101010101010101)
        rt = ((rt + R7) * GOLDEN) & MASK64
        rt ^= rol(rt, 0x17)
        if rt & 0xff == target:
            r = search(idx + 1, rt, counter + 1, S2, ri2, rj2, path + [guess])
            if r is not None:
                return r
    return None
```

## Flag

```
THEM?!CTF{Entr0py_C0r3_VM_S0_Funny!}
```

(*"Entropy Core VM, so funny."* The challenge is a VM, the VM has its
own quirks, the joke is the VM.)

## Defender notes

* **Custom VMs are still byte-shuffles.** A 30-opcode VM with 16
  registers and a jump table is a sharp speed bump in dynamic analysis,
  but every handler is one of: load, ALU, indexed load/store, branch,
  RC4 step, I/O. Once you've mapped them all, the bytecode is a
  conventional program with conventional structure (loop, counter,
  per-byte check). The only thing it bought the dev was forcing the
  player to write a small disassembler before they could even read the
  algorithm.
* **Treat the apparent "key length" register with suspicion.** The
  `R0 = 0xe8; RC4_KSA R0, 0x10` pair *looks* like the textbook
  `RC4_KSA(key_addr=0x10, key_len=232)`, and IMAGE[0x10..0xf8] is exactly
  232 bytes. The handler doesn't agree: it does `(i mod arg2) + R[r0]`,
  which makes the "length" register an *offset* into the key buffer and
  the "u16" operand the *length*. Don't trust naming heuristics — read
  the index expression.
* **Shifts handled differently from arithmetic is a real footgun.** The
  same 4-byte instruction width across ADD/MUL/XOR/SHL/ROL doesn't mean
  the same operand semantics. The disambiguation is the presence (or
  absence) of `andl $0xf` + register load between `movzbl` and the ALU
  op. A static disassembler can check this at handler-decode time;
  a hand emulator that templates over "4-byte 3-arg op" silently picks
  the wrong shift on every rotate.
* **Many-to-one hashes need backtracking, not greedy.** The per-byte
  avalanche is invertible *as a constraint* (find any byte producing the
  right low byte) but each position has multiple valid inputs and the
  state carries forward. A greedy solver works for the first few bytes
  (THEM?!) and then gets stuck. A depth-first search with an ASCII bias
  is two extra lines of code and turns a wedge into a closed-form solve.
* **Avalanche over rotate-by-constant is a textbook xorshift mixer.**
  Per-byte: `R10 = (R10 ^ input_rep + counter*RC4) * golden_ratio;
  R10 ^= ROL(R10, 23)`. That's a one-round xorshift\*-style mixer with
  an RC4-keyed counter to defeat trivial "type the same byte twice"
  collisions and a `multiply by phi` step to spread the bits. It's nice
  CTF design — small, deterministic, hard to brute, easy to verify once
  you see it. As a *production* anti-tamper, it has the usual problem
  with custom mixers: a state-recovery attacker only needs to solve a
  constraint per byte, so it never adds more bits of security than its
  output channel reveals (here, 8 bits per input).

## Files

* [`solve.py`](./solve.py) — argparse-driven solver. Reads `entropy_core.exe`,
  extracts the 16-byte RC4 key from IMAGE[0xe8..0xf8] and the 36-byte
  ciphertext from IMAGE[0xf8..0x11c], runs the per-byte hash backwards
  via DFS with a printable-ASCII preference, prints the flag. Standard
  library only.
* [`handout/entropy_core.exe`](./handout/entropy_core.exe) — original
  challenge binary.

## Requirements

Python 3.9+; standard library only.
