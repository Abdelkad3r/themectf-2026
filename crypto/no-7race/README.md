# No 7race (crypto)

| Field    | Value                                                            |
| -------- | ---------------------------------------------------------------- |
| Category | crypto                                                           |
| Handout  | `challenge.py` (one big-integer constraint, no ciphertext)       |
| Flag     | `THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}`                               |

## Description

```python
# challenge.py
import sys
sys.set_int_max_str_digits(1000000)

flag = open("flag.txt","rb").read()
if len(flag) > 50:
    exit()

a = int.from_bytes(open("flag.txt","rb").read(), byteorder='big')

b = a << 77777
b = str(b)
if not b.endswith('030811276925339139973812286584189287804214161881033394587'
                  '700362803979294502979595578120894393310544929228768540765'
                  '47798835969658432397983993314299716042752'):
    exit()
```

The handout never prints anything. It reads `flag.txt`, treats it as a
big-endian integer `a`, computes `a << 77777`, converts the result to a
decimal string, and *gates* on that decimal string ending with a fixed
**155-digit** suffix. The intended attack is to invert this — recover
`a` from the suffix alone — then read the bytes back as ASCII.

## TL;DR

`b.endswith(target_decimal_155)` is equivalent to

```
a * 2^77777 ≡ target  (mod 10^155)
```

with `target = int(suffix)` (≈ 3.08·10^153). Factoring the modulus:

```
10^155 = 2^155 · 5^155
```

apply CRT:

* **mod 2^155**: `2^77777 ≡ 0 (mod 2^155)` because 77777 ≫ 155, so the
  constraint forces only `target ≡ 0 (mod 2^155)`. The handout's suffix
  satisfies this — but it tells us *nothing* about `a` (every `a` works
  modulo a power of two ≤ the shift).
* **mod 5^155**: `gcd(2, 5) = 1`, so `2^77777` is invertible. Compute
  `inv = pow(2, -77777, 5**155)`, set `a ≡ target · inv (mod 5^155)`.
  This pins `a` to one residue class.

`5^155 ≈ 2^359.7`, and the flag is ≤ 50 bytes = 2^400. The single class
contains exactly one *small* representative — convert
`a mod 5^155` straight to bytes:

```
THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}
```

Exactly 32 ASCII bytes. ("Number theorem is fun.")

```
$ ./solve.py
[+] target has 155 decimal digits
[+] working modulus is 10^155 = 2^155 · 5^155
[+] recovered a mod 5^155: 32 bytes
THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}
```

## Recon

### Step 1 — re-state the constraint arithmetically

`str(b).endswith(suffix)` says: when you write `b` in base 10, the last
`len(suffix)` digits match `suffix`. That's literally

```
b mod 10^len(suffix)  ==  int(suffix)
```

`len(suffix) = 155`. `b = a · 2^77777`. So

```
a · 2^77777  ≡  T  (mod 10^155)
```

where `T = int(suffix) = 3081127692533913997…6042752` (the leading
`0` is significant for the *string match* but absorbs into the
integer).

No ciphertext, no oracle — a linear constraint on `a` modulo a
composite. Number-theory toy.

### Step 2 — factor the modulus and split

`10^155 = 2^155 · 5^155`. CRT says the constraint splits into

```
(i)  a · 2^77777 ≡ T  (mod 2^155)
(ii) a · 2^77777 ≡ T  (mod 5^155)
```

independently.

**(i)** `2^77777 mod 2^155`. Since `77777 > 155`, `2^77777 ≡ 0 mod 2^155`,
so the LHS is `0` for every `a`. The constraint is then `T ≡ 0
(mod 2^155)`, which is just a consistency test on the published suffix
— `T % 2**155` should equal 0, and it does:

```python
>>> T = int(open_suffix)
>>> T % (2**155)
0
```

Good, the challenge is well-posed. But (i) gives no information about
`a` — the shift by 77777 has eaten 77777 bits of precision; everything
in the low 155 bits is lost.

**(ii)** `gcd(2, 5) = 1`, so `2^77777` is a unit in `Z/5^155`. Compute
its inverse:

```python
inv = pow(2, -77777, 5**155)
a_mod5 = (T * inv) % (5**155)
```

That's a unique residue class of size `5^155 ≈ 2^359.7`.

### Step 3 — use the size bound to pick a unique representative

The handout pre-checks `len(flag) <= 50`, so `a < 256^50 = 2^400`. Our
residue class mod `5^155` has spacing `5^155 ≈ 2^359.7`, so within
`[0, 2^400)` there are at most `2^400 / 2^359.7 ≈ 2^40.3` candidates.
That's too many to bound naïvely — but the smallest representative is
the one with `a < 5^155 ≈ 2^359.7`, i.e. the value of `a_mod5` itself.

Convert to bytes:

```python
nbytes = (a_mod5.bit_length() + 7) // 8     # 32
flag   = a_mod5.to_bytes(nbytes, "big")     # b'THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}'
```

Length 32. All ASCII printable. Matches the THEM?! flag format. Done.

### Step 4 — verify the round trip

End-to-end sanity:

```python
a = int.from_bytes(b'THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}', 'big')
b = a << 77777
assert str(b).endswith(suffix)
```

Passes. The recovered string really is the flag the script accepts.

## Flag

```
THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}
```

## Defender notes

* **"No 7race" is a leetspeak double pun.** "No Trace" — the
  multiplication-by-power-of-two leaves *no trace* of the original
  binary structure in the visible suffix (all factors of 2 are absorbed
  into the high bits, exactly the `mod 2^155` half of CRT). And `7race ≈
  Trace` — the "no trace" is itself a half-truth, because the
  **multiplicative** half of the modulus (the `5^155` component) retains
  every bit of `a` modulo 5^155.
* **Left-shift is not a one-way function.** A frequent CTF-author
  mistake: "I shifted by 77777 bits, no one can recover it." But
  `shift by k` is just `mul by 2^k`, and multiplication is invertible
  modulo any coprime number — including `5^k` for the matching
  power-of-5 factor of the *display modulus*. The lesson generalises:
  if you publish `f(a) mod N` and `N = m·n` with `gcd(m, n) = 1`,
  every prime factor of `N` that doesn't divide the multiplier becomes
  a leak channel.
* **Hensel / CRT lifting is the bread-and-butter tool.** Whenever the
  constraint is "X is true modulo a composite," step one is always
  *factor the composite and look at each prime power separately*. Half
  of CTF crypto reduces to noticing that `2^large` ≡ 0 mod 2^small, or
  that `Z/p` admits modular inverses, or both.
* **Length gates ≠ uniqueness.** The handout's `len(flag) > 50: exit()`
  is meant to cap brute-force, but it incidentally guarantees the
  smallest residue class representative is the answer. If the gate had
  been `len(flag) > 80` the residue class would still contain ~2^81
  candidates ≤ 2^640 and you'd need a stronger filter (e.g., ASCII-only
  check, format string). Always think about how a length gate
  *interacts* with the algebraic constraint you've published.

## Files

* [`solve.py`](./solve.py) — argparse-driven solver. Strips the suffix
  from the source, verifies `target % 2^155 == 0`, computes the modular
  inverse `pow(2, -77777, 5**155)`, recovers `a mod 5**155`, converts to
  bytes, prints the flag. Round-trip-checks against the original
  constraint. Standard library only (needs
  `sys.set_int_max_str_digits` for the verification step).
* [`handout/challenge.py`](./handout/challenge.py) — the original
  one-shot checker.

## Requirements

Python 3.11+ (`pow(b, -e, m)` with negative exponent — `gmpy2` is *not*
required). Standard library only.
