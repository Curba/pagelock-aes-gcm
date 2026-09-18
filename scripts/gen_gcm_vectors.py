#!/usr/bin/env python3
"""Generate golden AES-GCM page vectors for the SystemVerilog benches.

Default (no arguments) regenerates the AES-128 / 256-byte set used by the
legacy benches, byte-identical to the original sec_cipher vectors:

  KEY = 2b7e151628aed2a6abf7158809cf4f3c
  IV  = cafebabefacedbaddecaf888
  AAD = feedfacedeadbeeffeedfacedeadbeef
  PT  = bytes(i & 0xff for i in range(224))
  ->  tb/vectors/ct.hex (14 lines), tb/vectors/tag.hex (1 line)

With --all it also writes the sets consumed by tb_aes_gcm_param.sv:
  tb/vectors/ct_k<KEY_W>_p<PAGE_BYTES>.hex / tag_k<KEY_W>_p<PAGE_BYTES>.hex
for every (KEY_W, PAGE_BYTES) in PARAM_SETS. AES-256 uses the FIPS-197
Appendix C.3 key. Any other geometry: --key-w 256 --page-bytes 528.

The reference is the `cryptography` package (validated against NIST CAVP by
tb/conformance/nist_ref_validation.py); pycryptodomex is used as a second
opinion when it is installed.
"""

import argparse
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
VEC_DIR = ROOT / 'tb' / 'vectors'

KEY128 = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
KEY256 = bytes.fromhex('603deb1015ca71be2b73aef0857d7781'
                       '1f352c073b6108d72d9810a30914dff4')
IV = bytes.fromhex('cafebabefacedbaddecaf888')
AAD = bytes.fromhex('feedfacedeadbeeffeedfacedeadbeef')
META_BYTES = 32

# Geometries exercised by tb/sv/integration/tb_aes_gcm_param.sv
PARAM_SETS = [(256, 64), (128, 48), (256, 528), (256, 256)]


def gcm_page(key_w: int, page_bytes: int):
    if key_w not in (128, 256):
        raise SystemExit(f'KEY_W must be 128 or 256, got {key_w}')
    if page_bytes % 16 or page_bytes < META_BYTES + 16:
        raise SystemExit(f'PAGE_BYTES must be a multiple of 16 and >= 48, got {page_bytes}')
    key = KEY128 if key_w == 128 else KEY256
    payload = page_bytes - META_BYTES
    pt = bytes(i & 0xFF for i in range(payload))
    raw = AESGCM(key).encrypt(IV, pt, AAD)
    ct, tag = raw[:-16], raw[-16:]
    try:  # optional second opinion
        from Cryptodome.Cipher import AES
        c = AES.new(key, AES.MODE_GCM, nonce=IV, mac_len=16)
        c.update(AAD)
        ct2, tag2 = c.encrypt_and_digest(pt)
        assert (ct2, tag2) == (ct, tag), 'cryptography and pycryptodomex disagree'
    except ImportError:
        pass
    return key, pt, ct, tag


def write_set(key_w: int, page_bytes: int, suffix: str) -> None:
    key, pt, ct, tag = gcm_page(key_w, page_bytes)
    VEC_DIR.mkdir(parents=True, exist_ok=True)
    ct_path = VEC_DIR / f'ct{suffix}.hex'
    tag_path = VEC_DIR / f'tag{suffix}.hex'
    with ct_path.open('w') as f:
        for i in range(len(ct) // 16):
            f.write(ct[i * 16:(i + 1) * 16].hex() + '\n')
    with tag_path.open('w') as f:
        f.write(tag.hex() + '\n')
    print(f'AES-{key_w} page {page_bytes} B ({len(ct) // 16} blocks): '
          f'key={key.hex()} tag={tag.hex()} -> {ct_path.name}, {tag_path.name}')


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--key-w', type=int, default=None)
    ap.add_argument('--page-bytes', type=int, default=None)
    ap.add_argument('--all', action='store_true', help='also write every PARAM_SETS geometry')
    a = ap.parse_args()

    if a.key_w or a.page_bytes:
        k = a.key_w or 128
        p = a.page_bytes or 256
        write_set(k, p, f'_k{k}_p{p}')
        return 0

    write_set(128, 256, '')            # legacy default set
    if a.all:
        for k, p in PARAM_SETS:
            write_set(k, p, f'_k{k}_p{p}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
