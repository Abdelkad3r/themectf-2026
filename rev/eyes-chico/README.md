# Eyes Chico (rev)

| Field    | Value                                                            |
| -------- | ---------------------------------------------------------------- |
| Category | rev                                                              |
| Target   | `1983.exe` — 22.5 KB, PE32+ console x86-64 (MinGW GCC 15.2.0)    |
| Flag     | `THEM?!CTF{R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL}` |

## Description

> `1983.exe`. Console crackme. Prompt:
>
>     flag>
>
> Type the right thing → `correct`. Anything else → `wrong`.

113 bytes of input compared against a value the program computes for
itself through a deliberately hostile control-flow-flattened VM with a
state vector that mutates *during* its own dispatch. The flag spells
out exactly what's been done to you:

> "Reverse-execution VM with mutating registers and control flow
> flattening makes static analysis painful."

## TL;DR

* Strings: `flag> `, `correct`, `wrong`, plus stack-built scraps like
  `setybdetI`, `arenegylI`, `modnarodH`, `uespemosI` (readable as
  reversed dwords — *Idetbytes / Ilegenra / Hdorandom / Isomepsue*).
  Throwaway flavour.
* `main` at `0x140002a40`. After CRT init, it runs a flat dispatcher
  that walks a 491-byte instruction tape at `.rdata+0x580`, indexes a
  36-entry jump table at `.rdata+0x18`, and writes 113 bytes one at a
  time into a stack buffer at `[rsp+0xbf]`. The check is a SIMD
  XOR-and-fold (`pxor` 16-byte chunks of input vs buffer, `por`
  into `xmm1`, horizontal-reduce, branch on zero).
* The VM's prologue **mutates state during dispatch**:

  ```
  k = ((ecx*2) XOR r11 XOR state[state[8]] XOR opcode) & 3
  state[esi]          ^= ...
  state[state[14]]    ^= ...
  state[state[15]]    ^= ...
  ```

  Same opcode value at two different points has different side effects.
  CFG flattening on top + a "WRONG-EXIT" sink as the default jump-table
  target makes static recovery a slog.
* Dynamic emulation walks straight past all of it. Map every PE
  section in Unicorn at its preferred VA, replicate `main`'s exact
  prologue (state seed, register values, stack layout), jump to the VM
  dispatcher entry, and hook every write into `[rsp+0xbf … +0x130)`.
  When RIP reaches the `leaq "flag> ", %rcx` instruction the VM has
  terminated and the buffer is fully populated — read 113 bytes and
  print them.

```
$ python3 -m pip install unicorn
$ ./solve.py
[+] loaded .text    at 0x140001000 size 0x2400
[+] loaded .data    at 0x140004000 size 0x200
[+] loaded .rdata   at 0x140005000 size 0x1400
...
[+] emulating 0x140002ac0 -> 0x140002b80
THEM?!CTF{R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL}
```

## Recon

### Step 1 — binary triage

```
$ file 1983.exe
1983.exe: PE32+ executable (console) x86-64 (stripped to external PDB),
          BuildID[sha1]=2525d7…, for MS Windows

$ strings 1983.exe | grep -iE 'flag|correct|wrong'
flag>
correct
wrong

$ strings 1983.exe | grep -E '^[a-zA-Z]{6,}I?$'
setybdetI       arenegylI       modnarodH       uespemosI
```

The last four are stack-built strings stored as little-endian dwords:
read them backwards and you get `Idet bytes`, `Ilegenra`, `Hdorandom`,
`Isomepsue` — flavour text the program never actually prints. Not the
flag, not a hint. Discard.

`nm` shows only `main` and `read` exported; everything else is
stripped. The real meat is in `main` (`0x140002a40`).

### Step 2 — main's vulnerable read

```
  140002b80:  leaq    0x2479(%rip), %rcx    # "flag> "
  140002b87:  call    fputs
  ...
  140002b9f:  call    fgets-equivalent
  140002bbc:  movb    $0, 0x130(%rsp,%rax)  # null-terminate at length
  140002bc4:  cmpq    $0x71, %rax           # 0x71 == 113
  140002bc8:  jne     <FAIL>
```

So input is read into `[rsp+0x130]` and the length is hard-gated at
**113** bytes (`0x71`). Anything else → fail.

### Step 3 — the equality check

After the length gate, main runs a SIMD XOR-OR-fold over two
113-byte regions:

```nasm
leaq 0xbf(%rsp), %rax           ; rax = expected buffer
leaq 0x1a0(%rsp), %rdx          ; rdx = end of compare
pxor %xmm1, %xmm1
loop:
  movdqu (%rax), %xmm0           ; load 16 bytes of expected
  pxor   (%r13), %xmm0           ; XOR with 16 bytes of input
  addq   $0x10, %r13
  addq   $0x10, %rax
  por    %xmm0, %xmm1
  cmpq   %rdx, %rax
  jne    loop
; tail byte at offset 112:
movzbl 0x12f(%rsp), %edx
xorl   0x1a0(%rsp), %edx
; horizontal OR-reduce xmm1 down to al
; final test: (al | dl) == 0 ?
```

i.e. constant-time `memcmp(input, expected, 113)`. The **expected
buffer at `[rsp+0xbf]` is what we need**.

That buffer is filled by everything that runs *before* the `flag> `
prompt.

### Step 4 — the VM

Skipping back to the top of `main` after the CRT shims:

```
  140002ac0:  ...   ; VM dispatcher entry
  ...
  140002b80:  leaq "flag> ", %rcx        ; VM has terminated
```

In that ~0xC0 bytes lies the entire computation. The setup hands the
dispatcher:

* `r14 = 0x140005580` — the **instruction tape** (491 bytes,
  `.rdata` offset 0x580, 3-byte instructions, terminated by an opcode
  outside the table's range).
* `r15 = 0x140005018` — base of the **jump table** (36 entries × i32,
  signed offsets relative to `r15`).
* `r12 = 0` — the program counter into the tape (`r12 += 3` per step).
* `r13 = rsp + 0x130` — a scratch sink for the per-iter 8-byte mutation
  log (the dispatcher writes its work into here, then later folds it
  back into the state).
* `[rsp+0xa8] | [rsp+0xb0]` — the **16-byte state vector**, seeded from
  two `.rdata` constants:
  * `0x140005770: 07 38 69 9a cb fc 2d 5e` (arithmetic progression
    `0x07 + 0x31·i`)
  * `0x140005778: 00 01 02 03 04 05 06 07`

The dispatcher's *prologue* (run before every handler) does:

```
edx  = state[esi]                        ; esi walks the state
ecx  = (ecx * 2) XOR r11
ecx ^= state[state[8]]                   ; double-indirect state read
ecx ^= ebx                               ; ebx = current opcode
k    = ecx & 3
state[esi]          = transform(state[esi], k)
state[state[14]]    = transform(..., k)
state[state[15]]    = transform(..., k)
```

— so **the state mutates before the handler even runs**, and the
mutation depends on what's at `state[state[8]]` (a double-indirect
read of the state itself). The same opcode at two different PCs has
different side effects.

The jump table at `r15` has 36 entries; only 15 of them (opcodes 1, 2,
4, 5, 7, 9, 11, 12, 17, 19, 23, 25, 29, 31, 35) route to *real*
handlers. The other 21 entries all point to the same `WRONG-EXIT`
sink — textbook control-flow-flattening "junk slots" whose only purpose
is to break naïve dispatcher analysis.

Each real handler does some combination of state arithmetic and ends
with a `jmp 0x140002c95` (the per-iter 8-byte write loop + state
post-fold). Every iteration that survives the dispatcher emits **one
byte** of the expected buffer into `[rsp+0xbf + i]` (the byte derived
from current state at the iteration's end).

### Step 5 — why static is hostile

Manually unwinding this:

1. The state mutates per dispatch, with the mutation parameterised by
   *the state itself* (double-indirection on `state[state[8]]`).
2. The dispatcher's exit jumps into a shared post-handler at
   `0x140002c95`, so every handler converges then diverges — CFG
   flattening, on top of the data-dependent mutation.
3. Half the table is junk slots leading to the wrong-exit, which makes
   the *control* flow look like ~32 paths when only ~15 are live.
4. The 491-byte tape is sequential — not the dispatch table — so you
   can't even just enumerate "which handlers ever run" from the table
   alone; you have to interpret the tape.

The flag literally calls this out:

```
..._MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL
```

So we don't do static.

### Step 6 — dynamic recovery with Unicorn

The check is XOR-equal, so **the buffer at `[rsp+0xbf]` IS the
expected input** — we don't need to *invert* anything, we just need to
let the VM run until it has finished filling that buffer, then read it.

Setup:

```python
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x140000000, 0x20000, UC_PROT_ALL)

# parse PE sections, load each at its vaddr
for name, vaddr, raw_off, raw_size in pe_sections(data):
    mu.mem_write(0x140000000 + vaddr, data[raw_off:raw_off + raw_size])

# allocate stack
mu.mem_map(0x10000000, 0x100000, UC_PROT_ALL)
rsp = 0x10000000 + 0x100000 - 0x1000

# replicate main's prologue exactly
mu.mem_write(rsp + 0xb8, b"\0" * 0x78)              # rep stosq region
mu.mem_write(rsp + 0xb0, mem(0x140005770, 8))       # state seed lo
mu.mem_write(rsp + 0xa8, mem(0x140005778, 8))       # state seed hi
mu.reg_write(RSP, rsp)
mu.reg_write(R12, 0)                                 # PC
mu.reg_write(R11, 1)
mu.reg_write(RDX, 4)
mu.reg_write(RCX, 0x13579bd)
mu.reg_write(R13, rsp + 0x130)
mu.reg_write(R14, 0x140005580)                       # tape
mu.reg_write(R15, 0x140005018)                       # jump table
```

Then hook every memory write that lands in the expected-flag buffer
range `[rsp+0xbf, rsp+0x130)`:

```python
captured = [None] * 113
def write_hook(uc, access, addr, size, value, ud):
    for off in range(size):
        a = addr + off
        if rsp + 0xbf <= a < rsp + 0xbf + 113:
            captured[a - (rsp + 0xbf)] = (value >> (8 * off)) & 0xff
mu.hook_add(UC_HOOK_MEM_WRITE, write_hook)
```

And emulate from the VM entry to the `flag>` prompt:

```python
mu.emu_start(0x140002ac0, 0x140002b80)
print(bytes(captured).decode("latin-1"))
```

Output:

```
THEM?!CTF{R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL}
```

113 bytes (10 prefix + 101 content + 2 brace + null on the wire). Each
offset takes exactly **one** write, in monotonically increasing
position — consistent with the VM's per-iteration single-byte emit. The
text is its own commentary, as advertised.

## Flag

```
THEM?!CTF{R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL}
```

## Defender notes

* **The "Eyes Chico" title is a *Money Heist* (`La Casa de Papel`) cue.**
  The Inspector's "*¡Ojos, chico, ojos!*" line — "Eyes, kid, eyes" — is
  about keeping eye contact under interrogation. As a CTF hint that's
  pointing you at the right *kind* of eyes: the binary's static
  surface is unreadable (mutating registers, CFG flattening, double-
  indirected state index), so you have to *look* at it differently —
  with an emulator watching the writes, not a disassembler trying to
  reason about them. The binary filename `1983.exe` is a separate
  Orwell-adjacent throwaway; the *challenge*'s title is the one that
  points at the solve.
* **Reverse-execution VMs sound scary; they're not, dynamically.**
  CFG flattening + mutating registers + indirected state index all
  punish *static* analysis (you cannot constant-fold past
  `state[state[8]]` without already knowing the state). They do nothing
  to a `Uc` harness — the CPU executes the same instructions either way,
  and a memory-write hook reads off whatever the program plants in
  memory regardless of how confusing the path to plant it was.
* **The check IS the answer when it's XOR-equal.** A common CTF
  shortcut: any verifier that does `memcmp(input, expected, N)` with
  `expected` *computed inside the binary* is offering you the answer
  for free in memory. The naïve `if input != expected` form is the
  same — language and library don't matter. The lesson for the
  defender: the verifier must combine the input with a secret the
  program never materialises (e.g., `expected = HMAC(secret, input)`
  with `secret` itself derived from another half of the input, or a
  hash-then-compare with `expected` only ever sitting in xmm
  registers).
* **PE32+ + MinGW dynamic loading is easy with Unicorn.** Real Windows
  loaders also fix up imports, resolve TLS, run constructors, etc. For
  a CTF crackme that only touches `main`'s own data, mapping every
  section at its preferred VA and skipping the CRT init call is enough.
  The 1983 binary doesn't import `LoadLibraryA` between `main`'s entry
  and the VM exit, so we get away without re-implementing the loader.
* **Junk dispatch slots are cheap to add and cheap to bypass.**
  21 of 36 jump-table entries pointing to `WRONG-EXIT` looks
  intimidating in static analysis, but a single-step trace ignores
  them entirely — you only see the 15 live handlers in the order the
  tape calls them. If you're designing a flattened VM as a real
  defence, the slots need to be *live and convincingly indistinguishable
  from the real handlers*, not stubs.

## Files

* [`solve.py`](./solve.py) — argparse-driven solver. Maps every PE
  section, seeds the stack and registers exactly the way `main` does,
  jumps to the VM dispatcher entry, hooks `UC_HOOK_MEM_WRITE` for
  the 113-byte expected-input buffer at `[rsp+0xbf]`, emulates until
  RIP reaches the `flag>` prompt, prints the recovered bytes. Requires
  `unicorn` (`pip install unicorn`).
* [`handout/1983.exe`](./handout/1983.exe) — the original challenge
  binary.

## Requirements

Python 3.9+ and [`unicorn`](https://www.unicorn-engine.org/) (CPU
emulator framework). `pip install unicorn`.
