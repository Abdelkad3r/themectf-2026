# Cascadino Chain (crypto)

| Field    | Value                                                            |
| -------- | ---------------------------------------------------------------- |
| Category | crypto                                                           |
| Handout  | four hex ciphertexts in a riddle (see `handout/challenge.txt`)   |
| Flag     | `THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}`                     |

## Description

> *"I built an unbreakable encryption chain, each key protects the next
>  and the last loops back to the start. There's no way in... right?"*
>
> c1: `36273f225d4e393b2414025f1030025f1030025f10301907035e145e0c082508520a0930001d081d1012`
> c2: `0e021b000e021b000e021b000e021b000e021b000e021b000e021b000e021b000e021b000e021b000e02`
> c3: `180504021805040218050402180504021805040218050402180504021805040218050402180504021805`
> c4: `202020204b49263932131d5d06371d5d06371d5d0637060515590b5c1a0f3a0a440d1632161a171f0615`

Four 42-byte ciphertexts. The riddle promises an "unbreakable chain" and
warns "there's no way in." Both are technically true and entirely
beside the point.

## TL;DR

A four-stage closed XOR loop:

```
c1 = flag XOR k1            ← k1 protects flag
c2 = k1   XOR k2            ← k2 protects k1
c3 = k2   XOR k3            ← k3 protects k2
c4 = k3   XOR flag          ← k3 loops back, protecting flag again
```

so `c1 XOR c2 XOR c3 XOR c4 == 0` — the "way in" the riddle dares you to
take really *is* a dead end. The actual crib is the flag format:

```
k1 = c1[0:4] XOR "THEM" = 62 6f 7a 6f = "bozo"
```

then `flag = c1 XOR ("bozo" repeated) = THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}`.

For the joke, the other two keys are exactly what you'd hope:

```
k2 = "bozo" XOR (c2 pattern 0x0e021b00) = "lmao"
k3 = "lmao" XOR (c3 pattern 0x18050402) = "them"
```

## Recon

### Step 1 — reading the hex

The four blobs are the same length (42 bytes = 84 hex chars each). Two
of them are *aggressively* periodic:

```
c2 = "0e021b00 0e021b00 0e021b00 … 0e02"      ← period 4
c3 = "18050402 18050402 18050402 … 1805"      ← period 4
```

c1 has a softer signal at offsets 10..21 — `"02 5f 10 30"` appears three
times in a row, then breaks — and c4 looks essentially random except for
the leading `"20 20 20 20"` (four spaces) and a similar 4-byte echo
later. So at least *some* of the underlying keys are 4-byte periodic.

### Step 2 — the closure

XOR all four:

```python
>>> bytes(a^b^c^d for a,b,c,d in zip(c1,c2,c3,c4))
b'\x00' * 42
```

Cleanly zero. That nails the structure: it's a **closed XOR cycle** of
four ciphertexts.

The cycle has 4 ciphertext equations in 4 unknowns (flag plus three
keys), but the closure means only 3 are independent — so you have one
degree of freedom even after using all the ciphertext. The "unbreakable"
boast is honest in the information-theoretic sense: from c1, c2, c3, c4
alone you cannot recover the flag without an additional constraint.

### Step 3 — keys are short

c2 has period 4 → `k1 XOR k2` has period 4 → both k1 and k2 have period
dividing 4 (and almost certainly equal to 4 — the alternative,
period 1 or 2, would force c2 to have shorter period too).

Same argument from c3 → k2 and k3 are 4-byte periodic.

c4 is *not* obviously periodic, which means whichever pair of keys
shows up in c4 must include at least one *non*-short key. Combined with
c2 and c3, the only consistent assignment is:

```
c4 = k3 XOR flag      (k3 is 4-byte periodic, flag is the long random thing)
```

That fixes the chain shape:

```
c1 = flag XOR k1     ← flag (42 bytes random) XOR k1 (4 bytes, repeated)
c2 = k1   XOR k2
c3 = k2   XOR k3
c4 = k3   XOR flag   ← the loop-back
```

### Step 4 — the consistency cross-check

If the model is right, two independent equations give the same XOR pattern:

```
c1 XOR c4 = (flag XOR k1) XOR (k3 XOR flag) = k1 XOR k3
c2 XOR c3 = (k1   XOR k2) XOR (k2 XOR k3) = k1 XOR k3
```

Compute both:

```
c2 XOR c3 = "0e021b00" XOR "18050402" = "16 07 1f 02"   (4-byte period)
c1[0:4]  XOR c4[0:4]  = "36 27 3f 22" XOR "20 20 20 20" = "16 07 1f 02"  ✓
```

Matches. The chain shape is correct, the keys are 4-byte, and the
one free parameter is k1 itself (4 bytes = 32 bits of unknown).

### Step 5 — the crib

THEM?! CTF flags begin `THEM?!CTF{`. The opening four bytes alone give
k1:

```
k1 = c1[0:4] XOR "THEM"
   = 36^54, 27^48, 3f^45, 22^4d
   = 62 6f 7a 6f
   = b"bozo"
```

Verifying against the next six bytes (the rest of the prefix) is
automatic — k1 is 4-byte periodic, so `c1[4..9] XOR "bozo bo"` should
produce `?!CTF{`:

```
c1[4..7] XOR "bozo" = 5d^62, 4e^6f, 39^7a, 3b^6f = 3f 21 43 54 = "?!CT"
c1[8..9] XOR "bo"   = 24^62, 14^6f                = 46 7b       = "F{"
```

Clean. k1 = `"bozo"`. Pulling the rest of the chain:

```
k2 = "bozo" XOR 0x0e021b00 = 6c 6d 61 6f = b"lmao"
k3 = "lmao" XOR 0x18050402 = 74 68 65 6d = b"them"
```

The keys are the literal words **bozo / lmao / them** — the running joke
of the THEM?! CTF organisers. The riddle's "unbreakable chain" is held
together by three four-letter words.

### Step 6 — decrypt

```python
>>> bytes(c1[i] ^ b"bozo"[i % 4] for i in range(42))
b'THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}'
```

Cross-check from the other end of the loop:

```python
>>> bytes(c4[i] ^ b"them"[i % 4] for i in range(42))
b'THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}'
```

Both routes give the same flag.

## Flag

```
THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}
```

The flag itself is also a tell — once you see the recovered plaintext,
the `"x0r_x0r_x0r_"` triplet *is* the period-4 echo you noticed in c1
at offsets 10..21 (`"02 5f 10 30"` repeated three times). The author
hid the answer in the structure of the ciphertext.

## Defender notes

* **Closed XOR cycles are information-theoretically secure against
  ciphertext-only attack on their own.** Four ciphertexts, four
  unknowns, three independent equations: you can recover *differences*
  of plaintexts but you cannot recover the plaintext itself without
  one further constraint. The "unbreakable" claim is technically true
  if the keys and the flag are independent uniform 42-byte values.
  Reality: the keys are 4 bytes wide (low entropy by design) and the
  flag has a fixed prefix.
* **Period-leak is the same flaw the Vigenère cipher dies from.**
  Once two ciphertexts in the chain are *periodic*, the period of the
  underlying keys leaks out instantly. Any honest implementation of
  this scheme would have to use full-length-random keys for each
  link — at which point you've reinvented the one-time pad.
* **Crib-based attacks are easier than they sound when the format is
  known.** THEM?!CTF flags begin with 10 fixed bytes. For a 4-byte key,
  4 of those bytes recover the key fully. Any CTF crypto challenge that
  doesn't randomise its plaintext prefix is one `bytes(c[i] ^ "THEM…"[i]) `
  call away from a solve.
* **Sum of all ciphertexts = 0 is a giveaway about chain shape.** The
  riddle's "there's no way in" line points directly at the XOR-sum:
  "the trivial attack doesn't work." In a CTF, the *interesting* attack
  almost always lives next to the one you're being told doesn't work.
  The XOR-sum dead end is also the diagnostic — if the four ciphertexts
  *didn't* XOR to zero, the chain wouldn't have the cyclic form, and
  the recovery would require a different model.
* **The keys make a joke.** This is just CTF flavour, but it's worth
  noting: `bozo`, `lmao`, `them` is a sequence that's hand-picked, not
  random. A reviewer should always check whether their "random-looking"
  key material is actually drawn from `/dev/urandom`; if your key fits
  inside a four-character ASCII word, you have already lost.

## Files

* [`solve.py`](./solve.py) — argparse-driven solver. Takes the four
  hex blobs (baked in), uses the `THEM?!CTF{` prefix as a 4-byte crib
  to recover `k1 = "bozo"`, decrypts `c1` to print the flag, and with
  `--verify` cross-checks by decrypting `c4` via `k3 = "them"` and
  printing all three keys. Standard library only.
* [`handout/challenge.txt`](./handout/challenge.txt) — the original
  challenge text (the four ciphertexts + the riddle).

## Requirements

Python 3.9+; standard library only.
