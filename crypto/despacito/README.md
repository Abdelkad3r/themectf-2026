# Despacito (crypto)

| Field    | Value                                                            |
| -------- | ---------------------------------------------------------------- |
| Category | crypto                                                           |
| Handout  | `ques.py` (DES-ECB encryptor) + `output.txt` (one base64 line)   |
| Flag     | `THEM?!CTF{D3S_4774K_W3S_AW3S0M3}`                               |

## Description

> `Despacito` — go slowly.

```python
# ques.py (lightly trimmed)
from Crypto.Cipher import DES
import base64
from FLAG import flag

def pad(plaintext):
    while len(plaintext) % 8 != 0:
        plaintext += b"*"
    return plaintext

def enc(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(plaintext))

key       = bytes.fromhex("E1E1E1E1F0F0F0F0")
plaintext = pad(flag)
print(enc(plaintext, key).decode())
```

```
# output.txt
T/tGpZNyHdhnf1oxwRmMPFcLiH//AfZdTpmYdp8daU0=
```

DES-ECB, `*`-padded plaintext, base64 ciphertext. The name "despacito"
suggests a slow attack. It isn't — it's instant once you read the key.

## TL;DR

DES has exactly four **weak keys** for which encryption equals
decryption (`E_k(E_k(P)) == P`):

```
0101010101010101
FEFEFEFEFEFEFEFE
1F1F1F1F0E0E0E0E
E0E0E0E0F1F1F1F1   <-- this one
```

The handout uses `E1E1E1E1F0F0F0F0`. Compare byte-by-byte against the
weak key:

```
E1 vs E0  ->  differ in bit 0  (LSB)
F0 vs F1  ->  differ in bit 0  (LSB)
```

Every byte's LSB is a **parity bit**: DES's Permuted Choice 1 keeps
only the 56 high bits of the 64-bit key. So `E1E1E1E1F0F0F0F0` schedules
to *exactly the same 56-bit key* as `E0E0E0E0F1F1F1F1`. The supplied
key is the weak key in parity-bit disguise.

With a weak key, encrypt == decrypt. Calling `cipher.decrypt` (or
`cipher.encrypt`) on the base64-decoded ciphertext yields the
plaintext directly:

```
THEM?!CTF{D3S_4774K_W3S_AW3S0M3}
```

— *"DES Attak Was Awesome"* — the flag is its own commentary.

```
$ ./solve.py
[+] key e1e1e1e1f0f0f0f0  -> weak after parity-strip? True
[+] decrypt == encrypt (weak-key cross-check passes)
THEM?!CTF{D3S_4774K_W3S_AW3S0M3}
```

## Recon

### Step 1 — read the script

`ques.py` does one thing: pads the flag to a multiple of 8 with the
byte `b"*"`, DES-ECB-encrypts under a hardcoded key, base64-encodes the
result.

* Padding: trailing `*`s. We'll strip those after decryption.
* Mode: ECB. Each 8-byte block is encrypted independently — no IV, no
  chaining.
* Key: 64-bit hex literal `E1E1E1E1F0F0F0F0`.
* Ciphertext (after base64-decode) = 32 bytes = 4 DES blocks.

The output is exactly 4 × 8 = 32 bytes, so the plaintext is 32 bytes
too. With the flag format `THEM?!CTF{...}` being ~30 characters of
content, that's a clean fit and almost certainly *no* `*` padding got
added.

### Step 2 — spot the weak key

DES's full weak-key table is small and worth memorising for CTFs.
After PC1 strips the parity bits (LSB of each byte) and splits into two
28-bit halves, four 64-bit key values produce halves that are all-zeros
or all-ones — so every round subkey is identical and the round function
becomes self-inverse:

```
   raw 64-bit              after parity-strip (msb 56 bits)
   ──────────────────      ──────────────────────────────────
   01 01 01 01 01 01 01 01  -> 28×0 || 28×0
   FE FE FE FE FE FE FE FE  -> 28×1 || 28×1
   1F 1F 1F 1F 0E 0E 0E 0E  -> 28×0 || 28×1
   E0 E0 E0 E0 F1 F1 F1 F1  -> 28×1 || 28×0
```

Now compare the handout's key:

```
   given:  E1 E1 E1 E1 F0 F0 F0 F0
   weak:   E0 E0 E0 E0 F1 F1 F1 F1
            ↓                   ↓
           bit 0 flipped in every byte
```

Each `E1` is `E0 | 0x01` and each `F0` is `F1 & 0xFE` — the parity
bits are flipped. The DES key schedule **does not see the parity
bits**. Both 64-bit values produce the same 56-bit working key, so
the supplied key is functionally identical to the weak key
`E0E0E0E0F1F1F1F1`.

A quick programmatic check:

```python
>>> def strip(k): return bytes(b & 0xFE for b in k)
>>> strip(bytes.fromhex("E1E1E1E1F0F0F0F0"))
b'\xe0\xe0\xe0\xe0\xf0\xf0\xf0\xf0'
>>> strip(bytes.fromhex("E0E0E0E0F1F1F1F1"))
b'\xe0\xe0\xe0\xe0\xf0\xf0\xf0\xf0'
>>> strip(bytes.fromhex("E1E1E1E1F0F0F0F0")) == strip(bytes.fromhex("E0E0E0E0F1F1F1F1"))
True
```

Matches.

### Step 3 — decrypt (or, equivalently, encrypt)

Because the schedule reduces to a single repeated subkey, the DES
round function under a weak key is involutive: 16 rounds with the
same subkey unwind themselves, and `E_k = D_k`. So:

```python
>>> from Crypto.Cipher import DES
>>> import base64
>>> ct = base64.b64decode("T/tGpZNyHdhnf1oxwRmMPFcLiH//AfZdTpmYdp8daU0=")
>>> key = bytes.fromhex("E1E1E1E1F0F0F0F0")
>>> DES.new(key, DES.MODE_ECB).decrypt(ct)
b'THEM?!CTF{D3S_4774K_W3S_AW3S0M3}'
>>> DES.new(key, DES.MODE_ECB).encrypt(ct)   # weak-key cross-check
b'THEM?!CTF{D3S_4774K_W3S_AW3S0M3}'
```

Both operations give the same plaintext — that's *the* signature of a
DES weak key, and it doubles as a sanity check that the solve is
correct.

### Step 4 — the name

`despacito` ("slowly") is a feint. The naïve attack on DES is a 2^56
keyspace sweep, which is "slow" by modern standards but not
intractable. A DES weak key turns it into one operation:
brute-force-vs-instant is the joke. The flag text `D3S_4774K_W3S_AW3S0M3`
("DES Attak Was Awesome") cements the punchline.

## Flag

```
THEM?!CTF{D3S_4774K_W3S_AW3S0M3}
```

## Defender notes

* **Weak keys are a known DES land-mine.** They're enumerable (four of
  them) and every serious library exposes them: PyCryptodome has
  `DES.new(key, ...)` raise `ValueError: Key is weak`… except it
  doesn't, not by default. OpenSSL has `DES_is_weak_key`. If you're
  hardcoding a DES key in 2026 you have already lost — but if you must,
  *at least* reject the four weak and twelve semi-weak keys at load
  time.
* **Parity bits cost nothing to check.** DES keys are *defined* as
  64-bit values whose every 8th bit is an *odd-parity* bit over the
  preceding 7 bits. `E1 = 1110 0001` has odd parity; `E0 = 1110 0000`
  has even parity. The handout's key fails the parity test — a one-line
  guard at load time would have caught the disguise. Most DES libraries
  silently accept any 64-bit key, which is the reason this category of
  vulnerability has aged so well.
* **ECB is a separate problem this challenge didn't lean on.** Even with
  a strong (non-weak) DES key, ECB leaks structural information (equal
  plaintext blocks → equal ciphertext blocks). Here the message is one
  block of high-entropy flag content, so the ECB tell would have been
  hidden anyway. The lesson stands: prefer AEAD modes (GCM, ChaCha20-
  Poly1305) over raw ECB unless you have a very specific reason.
* **Single DES is *itself* deprecated.** NIST withdrew DES from
  FIPS-46-3 in 2005; the keyspace is brute-forceable in well under a
  day on modern hardware. 3DES (TDEA) gets you to ~112 bits effective,
  AES gets you to 128/256. No new system should be designed around
  single DES.
* **"Slow attack" pun.** When a CTF names a crypto challenge after a
  song that translates to "slowly," 80% of the time the joke is that
  the attack is *not* slow — it's a weak-key, repeated-key, broken-mode,
  or oracle-padding instant solve. Pattern-match accordingly.

## Files

* [`solve.py`](./solve.py) — argparse-driven solver. Takes the
  ciphertext and key on the command line (defaults to the handout's),
  checks the key against DES's weak-key table after parity-stripping,
  verifies the self-inverse property, prints the flag. Requires
  `pycryptodome` (`pip install pycryptodome`).
* [`handout/ques.py`](./handout/ques.py) — the original encryptor.
* [`handout/output.txt`](./handout/output.txt) — the base64 ciphertext.

## Requirements

Python 3.9+ and `pycryptodome` (for the `Crypto.Cipher.DES` module).
