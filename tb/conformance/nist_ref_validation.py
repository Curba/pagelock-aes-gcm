#!/usr/bin/env python3
# NIST AES-GCM reference validation — McGrew & Viega + CAVP .rsp file sweep
# for both AES-128 and AES-256.
# Author: Baris
# Date: 2026-06-01, AES-256 added 2026-09-18
#
# Validates the Python `cryptography` library's AESGCM against known-good
# vectors before trusting it to generate RTL test stimuli. Every cocotb suite
# and the SV golden vectors are derived from this reference model.
#
# CAVP vector files (gcmtestvectors.zip) come from:
#   https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/
#   -> Block Ciphers -> GCM -> Download test vectors
# The .rsp files live under tb/conformance/vectors/:
#   gcmEncryptExtIV128.rsp  gcmDecrypt128.rsp
#   gcmEncryptExtIV256.rsp  gcmDecrypt256.rsp
#
# Usage:
#   python3 tb/conformance/nist_ref_validation.py

from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def h(hex_str: str) -> bytes:
    """Hex string → bytes, tolerating empty strings."""
    s = hex_str.strip()
    return bytes.fromhex(s) if s else b""


def encrypt_split(key: bytes, iv: bytes, pt: bytes, aad: bytes):
    """Encrypt and split result into (ciphertext, tag)."""
    raw = AESGCM(key).encrypt(iv, pt, aad if aad else None)
    return raw[:-16], raw[-16:]


# ---------------------------------------------------------------------------
# PART A — McGrew & Viega test vectors (AES-128 TC1-TC4, AES-256 TC13-TC16)
# ---------------------------------------------------------------------------
# Source: "The Galois/Counter Mode of Operation (GCM)", McGrew & Viega 2004.
# 96-bit IV, 128-bit tag. Widely reproduced; see also NIST SP 800-38D App. B.

MV_VECTORS = [
    {
        "id": "TC1",
        "desc": "K=0, IV=0, no AAD, no PT (tag-only)",
        "key": "00000000000000000000000000000000",
        "iv":  "000000000000000000000000",
        "pt":  "",
        "aad": "",
        "ct":  "",
        "tag": "58e2fccefa7e3061367f1d57a4e7455a",
    },
    {
        "id": "TC2",
        "desc": "K=0, IV=0, no AAD, 16-byte zero PT",
        "key": "00000000000000000000000000000000",
        "iv":  "000000000000000000000000",
        "pt":  "00000000000000000000000000000000",
        "aad": "",
        "ct":  "0388dace60b6a392f328c2b971b2fe78",
        "tag": "ab6e47d42cec13bdf53a67b21257bddf",
    },
    {
        "id": "TC3",
        "desc": "K=feffe9..., IV=cafebabe..., no AAD, 64-byte PT",
        "key": "feffe9928665731c6d6a8f9467308308",
        "iv":  "cafebabefacedbaddecaf888",
        "pt":  (
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b391aafd255"
        ),
        "aad": "",
        "ct":  (
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091473f5985"
        ),
        "tag": "4d5c2af327cd64a62cf35abd2ba6fab4",
    },
    {
        "id": "TC4",
        "desc": "K=feffe9..., IV=cafebabe..., 20-byte AAD, 60-byte PT",
        "key": "feffe9928665731c6d6a8f9467308308",
        "iv":  "cafebabefacedbaddecaf888",
        "pt":  (
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39"
        ),
        "aad": "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "ct":  (
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091"
        ),
        "tag": "5bc94fbc3221a5db94fae95ae7121a47",
    },
    {
        "id": "TC13",
        "desc": "AES-256 K=0, IV=0, no AAD, no PT (tag-only)",
        "key": "00" * 32,
        "iv":  "000000000000000000000000",
        "pt":  "",
        "aad": "",
        "ct":  "",
        "tag": "530f8afbc74536b9a963b4f1c4cb738b",
    },
    {
        "id": "TC14",
        "desc": "AES-256 K=0, IV=0, no AAD, 16-byte zero PT",
        "key": "00" * 32,
        "iv":  "000000000000000000000000",
        "pt":  "00000000000000000000000000000000",
        "aad": "",
        "ct":  "cea7403d4d606b6e074ec5d3baf39d18",
        "tag": "d0d1c8a799996bf0265b98b5d48ab919",
    },
    {
        "id": "TC15",
        "desc": "AES-256 K=feffe9..., IV=cafebabe..., no AAD, 64-byte PT",
        "key": "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "iv":  "cafebabefacedbaddecaf888",
        "pt":  (
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b391aafd255"
        ),
        "aad": "",
        "ct":  (
            "522dc1f099567d07f47f37a32a84427d"
            "643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838"
            "c5f61e6393ba7a0abcc9f662898015ad"
        ),
        "tag": "b094dac5d93471bdec1a502270e3cc6c",
    },
    {
        "id": "TC16",
        "desc": "AES-256 K=feffe9..., IV=cafebabe..., 20-byte AAD, 60-byte PT",
        "key": "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "iv":  "cafebabefacedbaddecaf888",
        "pt":  (
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39"
        ),
        "aad": "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "ct":  (
            "522dc1f099567d07f47f37a32a84427d"
            "643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838"
            "c5f61e6393ba7a0abcc9f662"
        ),
        "tag": "76fc6ece0f4e1768cddf8853bb2d551b",
    },
]


def run_part_a() -> tuple[int, int]:
    print("=" * 60)
    print("PART A — McGrew & Viega AES-128 and AES-256 vectors")
    print("=" * 60)
    passed = failed = 0

    for v in MV_VECTORS:
        key = h(v["key"])
        iv  = h(v["iv"])
        pt  = h(v["pt"])
        aad = h(v["aad"])
        exp_ct  = h(v["ct"])
        exp_tag = h(v["tag"])

        got_ct, got_tag = encrypt_split(key, iv, pt, aad)

        ok_ct  = got_ct  == exp_ct
        ok_tag = got_tag == exp_tag

        if ok_ct and ok_tag:
            print(f"  PASS  {v['id']}: {v['desc']}")
            passed += 1
        else:
            print(f"  FAIL  {v['id']}: {v['desc']}")
            if not ok_ct:
                print(f"         CT  exp: {exp_ct.hex()}")
                print(f"         CT  got: {got_ct.hex()}")
            if not ok_tag:
                print(f"         TAG exp: {exp_tag.hex()}")
                print(f"         TAG got: {got_tag.hex()}")
            failed += 1

    print(f"\n  Part A result: {passed} passed, {failed} failed\n")
    return passed, failed


# ---------------------------------------------------------------------------
# PART B — CAVP .rsp file sweep
# ---------------------------------------------------------------------------

def parse_headers(line: str) -> dict:
    """Parse a bracketed header line like '[Keylen = 128]' into a dict entry."""
    result = {}
    for token in line.split("]"):
        token = token.strip().lstrip("[")
        if "=" in token:
            k, _, v = token.partition("=")
            result[k.strip()] = v.strip()
    return result


def parse_rsp(path: Path) -> list[dict]:
    """Parse a CAVP .rsp file into a list of vector dicts.

    Vectors are delimited by blank lines. Encrypt files end each vector with
    'Tag'; decrypt files end with 'PT = ...' or 'FAIL'. Using blank lines as
    the delimiter handles both formats uniformly.
    """
    vectors = []
    headers = {}
    current: dict = {}

    def flush():
        if "Key" in current:
            vec = dict(headers)
            vec.update(current)
            vectors.append(vec)
        current.clear()

    with path.open() as f:
        for raw in f:
            line = raw.strip()
            if line.startswith("#"):
                continue
            if not line:
                flush()
                continue
            if line.startswith("["):
                flush()
                headers.update(parse_headers(line))
                continue
            if line == "FAIL":
                current["FAIL"] = True
            elif "=" in line:
                k, _, v = line.partition("=")
                current[k.strip()] = v.strip()

    flush()  # last vector if no trailing blank line
    return vectors


def filter_geometry(vectors: list[dict], keylen: int) -> list[dict]:
    """Keep only AES-<keylen> / 96-bit IV / 128-bit tag vectors (the RTL geometry)."""
    return [
        v for v in vectors
        if v.get("Keylen") == str(keylen)
        and v.get("IVlen") == "96"
        and v.get("Taglen") == "128"
    ]


def run_encrypt_rsp(path: Path, keylen: int) -> tuple[int, int]:
    print(f"  File: {path.name} (AES-{keylen}, 96-bit IV, 128-bit tag subset)")
    vectors = filter_geometry(parse_rsp(path), keylen)
    passed = failed = 0

    for v in vectors:
        key    = h(v["Key"])
        iv     = h(v["IV"])
        pt     = h(v.get("PT", ""))
        aad    = h(v.get("AAD", ""))
        exp_ct  = h(v.get("CT", ""))
        exp_tag = h(v["Tag"])

        got_ct, got_tag = encrypt_split(key, iv, pt, aad)

        if got_ct == exp_ct and got_tag == exp_tag:
            passed += 1
        else:
            failed += 1
            idx = v.get("Count", "?")
            print(f"    FAIL count={idx}")
            if got_ct != exp_ct:
                print(f"      CT  exp: {exp_ct.hex()}")
                print(f"      CT  got: {got_ct.hex()}")
            if got_tag != exp_tag:
                print(f"      TAG exp: {exp_tag.hex()}")
                print(f"      TAG got: {got_tag.hex()}")

    return passed, failed


def run_decrypt_rsp(path: Path, keylen: int) -> tuple[int, int]:
    print(f"  File: {path.name} (AES-{keylen}, 96-bit IV, 128-bit tag subset)")
    vectors = filter_geometry(parse_rsp(path), keylen)
    passed = failed = 0

    for v in vectors:
        key    = h(v["Key"])
        iv     = h(v["IV"])
        ct     = h(v.get("CT", ""))
        aad    = h(v.get("AAD", ""))
        tag    = h(v["Tag"])
        expect_fail = v.get("FAIL", False)

        # cryptography lib expects ct||tag concatenated
        ciphertext_with_tag = ct + tag

        if expect_fail:
            try:
                AESGCM(key).decrypt(iv, ciphertext_with_tag, aad if aad else None)
                # Should have raised — that's a failure
                failed += 1
                print(f"    FAIL count={v.get('Count','?')}: expected InvalidTag but decrypt succeeded")
            except InvalidTag:
                passed += 1
        else:
            exp_pt = h(v.get("PT", ""))
            try:
                got_pt = AESGCM(key).decrypt(iv, ciphertext_with_tag, aad if aad else None)
                if got_pt == exp_pt:
                    passed += 1
                else:
                    failed += 1
                    print(f"    FAIL count={v.get('Count','?')}: PT mismatch")
                    print(f"      PT  exp: {exp_pt.hex()}")
                    print(f"      PT  got: {got_pt.hex()}")
            except InvalidTag:
                failed += 1
                print(f"    FAIL count={v.get('Count','?')}: unexpected InvalidTag on PASS vector")

    return passed, failed


def run_part_b(vectors_dir: Path) -> tuple[int, int]:
    print("=" * 60)
    print("PART B — CAVP .rsp file sweep (AES-128 and AES-256)")
    print("=" * 60)

    total_passed = total_failed = 0
    missing = []

    for keylen in (128, 256):
        enc_file = vectors_dir / f"gcmEncryptExtIV{keylen}.rsp"
        dec_file = vectors_dir / f"gcmDecrypt{keylen}.rsp"

        if enc_file.exists():
            print(f"\n  [Encrypt AES-{keylen}]")
            p, f = run_encrypt_rsp(enc_file, keylen)
            total_passed += p
            total_failed += f
            print(f"  -> {p} passed, {f} failed")
        else:
            missing.append(enc_file.name)

        if dec_file.exists():
            print(f"\n  [Decrypt AES-{keylen}]")
            p, f = run_decrypt_rsp(dec_file, keylen)
            total_passed += p
            total_failed += f
            print(f"  -> {p} passed, {f} failed")
        else:
            missing.append(dec_file.name)

    if missing:
        print(
            "\n  MISSING CAVP files: " + ", ".join(missing) + "\n"
            "  Download gcmtestvectors.zip from:\n"
            "    https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/\n"
            "  and place the .rsp files in tb/conformance/vectors/."
        )
        total_failed += len(missing)

    print(f"\n  Part B result: {total_passed} passed, {total_failed} failed\n")
    return total_passed, total_failed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    script_dir = Path(__file__).parent
    vectors_dir = script_dir / "vectors"

    a_pass, a_fail = run_part_a()
    b_pass, b_fail = run_part_b(vectors_dir)

    total_pass = a_pass + b_pass
    total_fail = a_fail + b_fail

    print("=" * 60)
    print(f"TOTAL: {total_pass + total_fail} vectors — {total_pass} PASSED, {total_fail} FAILED")
    print("=" * 60)

    if total_fail:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
