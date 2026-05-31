#!/usr/bin/env python3
"""End-to-end solver for the THEM?! 2026 "Ancient Signals" (rev) challenge.

There are two layers, both of which the same Python script can lift out:

  1.  `transmission.dat` is an 8-bit unsigned PCM WAV XOR-encrypted with a
      128-byte repeating key. Because 8-bit PCM encodes silence as 0x80,
      every silent region of the original WAV leaks the key directly
      (silence XOR key = key XOR 0x80). The first 128-byte silent block
      lives at file offset 0x50, so the full key is recoverable in one
      pass; XOR'ing it back out the rest of the file produces a clean
      RIFF/WAVE that plays (it's the Rick Astley song — that's the
      punchline).

  2.  The actual *flag* never touches the audio. `player.exe` carries a
      55-byte XOR-encrypted blob in its `.data` section. The XOR key is
      the FNV-1a hash of an 80-byte slice of `.text` — the body of a tiny
      anti-tamper "is_RIFF" helper at virtual address 0x1400032d0. Lift
      the hash from the binary, XOR the blob, print the flag.

The "corruption" framing in the brief is a fake-out: the player short-
circuits to "Frequencies misaligned" on the raw .dat, so even a working
emulator wouldn't display the flag. The static lift bypasses everything.
"""
import argparse
import struct
from pathlib import Path


# ---- Layer 1: transmission.dat -> WAV ----

def recover_wav(dat: bytes, silent_off: int = 0x50, period: int = 128) -> bytes:
    """Recover the WAV from the XOR-encrypted transmission.

    Silence in 8-bit unsigned PCM is 0x80, so over a silent region:
        enc[p]            = 0x80 XOR key[p % period]
    => key[p % period]    = enc[p] XOR 0x80
    The 128-byte block starting at silent_off is verified silent (it
    repeats at offset+128, offset+256, ...).
    """
    key = bytearray(period)
    for p in range(silent_off, silent_off + period):
        key[p % period] = dat[p] ^ 0x80
    return bytes(d ^ key[i % period] for i, d in enumerate(dat))


# ---- Layer 2: lift the flag out of player.exe ----

ImageBase   = 0x140000000
TEXT_VADDR  = 0x1000
TEXT_RADDR  = 0x400
DATA_VADDR  = 0x80000
DATA_RADDR  = 0x7f400

FNV_RANGE_VA   = (0x1400032d0, 0x140003320)   # is_RIFF helper body
ENC_BLOB_VA    = 0x140080000                  # start of .data
ENC_BLOB_LEN   = 55                           # 0x37, the XOR loop length

FNV_OFFSET = 0x811c9dc5
FNV_PRIME  = 0x01000193


def va_to_file_offset(va: int, sec_vaddr: int, sec_raddr: int) -> int:
    return va - ImageBase - sec_vaddr + sec_raddr


def fnv1a(buf: bytes) -> int:
    h = FNV_OFFSET
    for b in buf:
        h = ((h ^ b) * FNV_PRIME) & 0xFFFFFFFF
    return h


def lift_flag(pe: bytes) -> str:
    start, end = FNV_RANGE_VA
    fnv_off = va_to_file_offset(start, TEXT_VADDR, TEXT_RADDR)
    fnv_bytes = pe[fnv_off:fnv_off + (end - start)]
    h = fnv1a(fnv_bytes)
    key = h.to_bytes(4, "little")

    blob_off = va_to_file_offset(ENC_BLOB_VA, DATA_VADDR, DATA_RADDR)
    enc = pe[blob_off:blob_off + ENC_BLOB_LEN]
    return bytes(b ^ key[i & 3] for i, b in enumerate(enc)).decode("ascii")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--player", default="handout/player.exe", type=Path)
    ap.add_argument("--dat", default="handout/transmission.dat", type=Path)
    ap.add_argument("--wav-out", default="recovered.wav", type=Path,
                    help="path to write the recovered WAV (default: recovered.wav)")
    args = ap.parse_args()

    pe = args.player.read_bytes()
    dat = args.dat.read_bytes()

    wav = recover_wav(dat)
    args.wav_out.write_bytes(wav)
    print(f"[+] wrote recovered WAV to {args.wav_out} ({len(wav)} bytes)", flush=True)

    # quick WAV sanity check
    if wav[:4] == b"RIFF" and wav[8:12] == b"WAVE":
        fmt_off = wav.find(b"fmt ")
        if fmt_off >= 0:
            fmt_chunk = wav[fmt_off + 8:fmt_off + 24]
            af, nch, sr, br, ba, bps = struct.unpack_from("<HHIIHH", fmt_chunk)
            print(f"[+] WAV: fmt={af} channels={nch} rate={sr}Hz bits={bps}")

    flag = lift_flag(pe)
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
