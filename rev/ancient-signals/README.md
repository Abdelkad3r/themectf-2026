# Ancient Signals (rev)

| Field    | Value                                                            |
| -------- | ---------------------------------------------------------------- |
| Category | rev                                                              |
| Targets  | `player.exe` (Win64 PE32+ GUI, miniaudio + WinMM), `transmission.dat` |
| Flag     | `THEM?!CTF{1mag1n3_gett1ng_r1ckr0ll3d_1n_tH3M?!C7F_xDDD}`        |

## Description

> Our field agents recovered a secure comms package from an enemy operative.
> They built a makeshift tool to translate the weird signals into an audible
> frequency, but the extraction corrupted the software. Can you help us in
> fixing this software so we can hear what's on the tape?

Two-file challenge: a Windows GUI player (`player.exe`, built on top of
[miniaudio](https://miniaud.io/) + WinMM) and a binary payload
(`transmission.dat`). The brief tells you the *software* is corrupted and
implies the flag is on the *tape*. Both halves are misdirection — the real
flag lives inside the player's own `.data` section, locked behind a static
self-check.

## TL;DR

There are **two independent solves** that fall out of static analysis:

1. **The tape.** `transmission.dat` is an 8-bit unsigned PCM WAV XOR-
   encrypted with a 128-byte repeating key. Silence in 8-bit PCM is `0x80`,
   so any silent region of the original audio leaks the key directly. The
   block at file offset `0x50..0xCF` is one such region. Recover the key,
   XOR the file → clean `RIFF…WAVE`. The audio is the **Rick Astley song**.
   It is part of the joke; it is not the flag.
2. **The player.** `player.exe` carries a 55-byte XOR-encrypted blob at
   `.data` (VA `0x140080000`). The XOR key is the **FNV-1a hash** of an
   80-byte slice of `.text` — the body of a tiny *anti-tamper* helper at
   `0x1400032d0` that checks the first 4 bytes of its input are `"RIFF"`.
   Compute the hash, XOR the blob, the flag falls out:
   `THEM?!CTF{1mag1n3_gett1ng_r1ckr0ll3d_1n_tH3M?!C7F_xDDD}`.

```
$ ./solve.py
[+] wrote recovered WAV to recovered.wav (72176 bytes)
[+] WAV: fmt=1 channels=1 rate=8000Hz bits=8
THEM?!CTF{1mag1n3_gett1ng_r1ckr0ll3d_1n_tH3M?!C7F_xDDD}
```

## Why the brief lies about needing the player

If you wire the brief literally — "fix the software, hear the tape" — you
end up emulating Windows just to look at a Rick Astley song. The
flag-printing code path inside `player.exe` is gated by a `is_RIFF()`
check on the raw input bytes (the player never decrypts `transmission.dat`
itself; it expects it to *already* be a WAV). Since the raw `.dat` starts
`08 CE 08 25` not `RIFF`, the player short-circuits to its error branch
and prints "Frequencies misaligned". Even with Wine + audio output, the
flag never reaches the screen.

The static solve sidesteps the validation entirely.

## Recon

### transmission.dat — pattern in the noise

```
$ xxd transmission.dat | head -8
00000000: 08ce 0825 0a06 17bb bd76 08d6 14a2 52cb  ...%.....v....R.
00000010: 6ae7 6ec3 037f 371b 4a88 7ef3 d230 464b  j.n...7.J.~..0FK
00000020: 9b47 8623 6e96 052f 30f7 9e53 fbc1 20e4  .G.#n../0..S.. .
00000030: f3f4 e8d7 4c3f 76db 0636 c8d5 e4df a83a  ....L?v..6.....:
00000040: ec29 ffd3 529f f25a 1ed6 7c0a f34f 26eb  .)..R..Z..|..O&.
00000050: 7ae7 6ec3 027f 361b 0a97 7ef3 922f 464b  z.n...6...~../FK
00000060: 9a47 8e23 22df 567b 2af7 9e53 b28f 66ab  .G.#".V{*..S..f.
00000070: baa7 ae83 423f 76db 4a57 beb3 d2ef 860b  ....B?v.JW......
```

The 16-byte chunk at `0x50..0x5F` recurs every **128 bytes** from `0xD0`
onward, then disappears in the middle of the file, then comes back near
the end. That's the smoking gun of XOR-with-a-fixed-key over a region of
audio silence. The recurring chunk *is* a slice of the key XOR'd with
whatever silence is encoded as in this audio.

For **8-bit unsigned PCM** silence is `0x80` (the midpoint of the range,
since 0..255 maps to amplitude). So:

```python
key[p % 128] = data[p] ^ 0x80     for any p in a silent region
```

The block `0x50..0xCF` is silent (it repeats at `0xD0..0x14F` byte-for-byte,
which can only happen if both blocks decode to all-zero PCM samples), so
one pass gives the whole 128-byte key. XOR'ing the rest of the file
yields:

```
$ xxd recovered.wav | head -4
00000000: 5249 4646 e819 0100 5741 5645 666d 7420  RIFF....WAVEfmt
00000010: 1000 0000 0100 0100 401f 0000 401f 0000  ........@...@...
00000020: 0100 0800 4c49 5354 1a00 0000 494e 464f  ....LIST....INFO
00000030: 4953 4654 0e00 0000 4c61 7666 3630 2e31  ISFT....Lavf60.1
```

…which `wave.open()` reports as mono 8-bit PCM at 8000 Hz, ~9 s — Lavf
metadata says it came out of ffmpeg ("Lavf60.1"). The audio is the Rick
Astley song. It is *not* the flag, but it *is* the punchline.

### player.exe — finding the real flag path

`strings` against the PE turns up the relevant landmarks:

```
[SUCCESS] Signal locked.\r\n\nFLAG: %s
[ERROR] Signal corrupted.\r\nFrequencies misaligned.
SIGNAL DECRYPTED                                     ; MessageBoxA title
transmission.dat
transmission.dat missing!
```

Xref `"FLAG: %s"` (`0x140083ff8`) in radare2: lands inside `fcn.14002d580`
at `0x14002df68`. The function builds the `lpText` buffer at `rsp+0x70`
by way of a tight XOR loop just before:

```nasm
; .text:0x14002df20  — the flag decrypt loop, 0x37 = 55 bytes
loop:
  mov   rdx, rax                  ; rdx = i
  add   rcx, 1                    ; rcx = dst++
  and   edx, 3                    ; i & 3
  movzx edx, byte [rsp + rdx + 0x68]   ; key[i & 3]
  xor   dl,  byte [r8  + rax]          ; XOR encrypted[i]
  add   rax, 1                    ; i++
  mov   byte [rcx - 1], dl        ; dst[i] = plain
  cmp   rax, 0x37                 ; until i == 55
  jne   loop
```

So the flag is 55 bytes long, encrypted with a 4-byte key at `rsp+0x68`,
source at `r8`. Tracing `r8` and `rsp+0x68` upward:

* `r8 = lea section..data` → `0x140080000` — start of the `.data` section.
* `rsp+0x68` is initialised from the FNV-1a hash loop right before:

```nasm
; .text:0x14002dd6d  — FNV-1a state init and loop
  mov   edx, 0x811c9dc5             ; FNV-1a basis
  ...
loop:
  movzx ecx, byte [rax]             ; consume one byte
  add   rax, 1
  xor   edx, ecx                    ; FNV-1a step
  imul  edx, edx, 0x01000193        ; FNV prime
  cmp   rax, r8
  jne   loop
  mov   [rsp + 0x68], edx           ; key = hash
```

`0x811c9dc5` and `0x01000193` are the textbook FNV-1a constants. The
range being hashed is `rax = 0x1400032d0` to `r8 = 0x140003320` — **80
bytes** of `.text`.

### The function being hashed

`fcn.1400032d0` is exactly the helper this binary uses for *its own*
RIFF check:

```nasm
; .text:0x1400032d0  — is_RIFF(uint8_t *p)
  push  rbp
  mov   rbp, rsp
  mov   [rbp-0x10], rcx
  ...
  cmp   al, 0x52        ; 'R'
  jne   .fail
  ...
  cmp   al, 0x49        ; 'I'
  jne   .fail
  ...
  cmp   al, 0x46        ; 'F'
  jne   .fail
  ...
  cmp   al, 0x46        ; 'F'
  jne   .fail
  mov   eax, 1
  jmp   .done
.fail:
  mov   eax, 0
.done:
  pop   rbp
  ret
```

The hash is computed from the *bytes of the verification function
itself*. This is a classic anti-tamper pattern: if you patch
`is_RIFF` to always return 1 (a natural move for any reverser who notices
it's blocking the audio path), the FNV hash changes and the flag blob
decrypts to garbage. The integrity check protects the integrity check.

In the unpatched binary the hash is deterministic; we compute it ourselves
off-line.

## Exploit

```python
ImageBase   = 0x140000000
TEXT_VADDR  = 0x1000     ; .text section
TEXT_RADDR  = 0x400
DATA_VADDR  = 0x80000    ; .data section
DATA_RADDR  = 0x7f400

FNV_RANGE   = (0x1400032d0, 0x140003320)   ; 80 bytes
BLOB_VA     = 0x140080000                  ; 55 bytes XOR-encrypted

# Lift the 80-byte slice of .text that gets hashed
fnv_off  = FNV_RANGE[0] - ImageBase - TEXT_VADDR + TEXT_RADDR
fnv_buf  = pe[fnv_off : fnv_off + 80]

# FNV-1a
h = 0x811c9dc5
for b in fnv_buf:
    h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
key = h.to_bytes(4, "little")           # 0x81 0x1c 0x17 0xaa

# Lift and decrypt the 55-byte blob
blob_off = BLOB_VA - ImageBase - DATA_VADDR + DATA_RADDR
enc      = pe[blob_off : blob_off + 55]
flag     = bytes(b ^ key[i & 3] for i, b in enumerate(enc)).decode()
```

Result:

```
FNV-1a(.text[0x1400032d0:0x140003320]) = 0xaa171c81
4-byte XOR key (LE)                     = 81 1c 17 aa
enc                                     = d5 54 52 e7 be 3d 54 fe …
flag                                    = "THEM?!CTF{1mag1n3_gett1ng_r1ckr0ll3d_1n_tH3M?!C7F_xDDD}"
```

For completeness, the `solve.py` in this directory also recovers the
underlying WAV (Rick Astley) so you can verify the "tape" claim for
yourself — just for fun, the flag never depends on it.

## Flag

```
THEM?!CTF{1mag1n3_gett1ng_r1ckr0ll3d_1n_tH3M?!C7F_xDDD}
```

## Defender notes

* **Self-hash anti-tamper is brittle, but it's not theatre.** The FNV
  here protects the right thing — the helper that gates the
  flag-printing path — and any naive patch in radare2 or x64dbg
  invalidates the key. A reverser still wins by *not patching*, but the
  cost goes from "1 byte of `mov al, 1`" to "actually read the loop and
  lift constants." That's a real if modest speed bump. The catch is
  that the hash is computed at *runtime* from the live `.text`, so
  patching at runtime in a debugger after the hash has already been
  taken still works — the protection must be paired with re-validation
  (e.g. periodic re-hashing) to bite that case.
* **Don't put your secrets behind a side door you also documented.**
  This binary helpfully embeds the strings `[SUCCESS] Signal locked.`,
  `FLAG: %s`, and `SIGNAL DECRYPTED` plain-text in `.rdata`. The xref
  to *any* of them lands you within twenty instructions of the XOR
  loop. If the flag-print path has to exist, splatter unique strings
  to a single fmt buffer that's only assembled at runtime — at least
  force the reverser to dynamic analysis.
* **Misdirection in the brief is fair; misdirection in the binary is
  better.** The brief gestures hard at the WAV and the player's audio
  path. The actual flag never touches either: it's a static blob and
  a static hash. A defender who wanted to make this even harder could
  derive the XOR key from a *runtime* value (audio device GUID, file
  fingerprint of the legit `transmission.dat`, etc.) rather than a
  fixed hash of static `.text` — at the cost of needing dynamic
  emulation to recover.
* **8-bit unsigned PCM silence is `0x80`, not `0x00`.** Easy to forget
  if you live in 16-bit land. The same XOR-with-repeating-key trick on
  *signed* 16-bit silence would have left no recurring pattern at all
  for the attacker to grab onto.

## Files

* [`solve.py`](./solve.py) — argparse-driven solver. Recovers the WAV
  (writes `recovered.wav` if you want to listen), computes the FNV-1a
  over `.text[0x1400032d0:0x140003320]`, XORs the 55-byte blob at
  `.data:0x140080000`, prints the flag.
* [`handout/player.exe`](./handout/player.exe) — original Win64 PE.
* [`handout/transmission.dat`](./handout/transmission.dat) — the
  XOR-encrypted WAV.

## Requirements

Python 3.9+; no third-party deps. (No fpylll, no Sage, no Wine. The
whole thing is byte arithmetic.)
