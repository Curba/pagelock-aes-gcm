# AES-GCM known-answer tests (KAT) using cocotb. Geometry-agnostic: key size
# and payload length come from aes_gcm_driver (environment).
# Reference model: Python cryptography.hazmat AESGCM.
# Author: Baris
# Date: 2026-06-01
#
# Three test functions:
#   test_encrypt_kat  — 5 deterministic vectors, compare CT + tag
#   test_decrypt_kat  — decrypt RTL-produced CT, compare PT + tag_ok=1
#   test_decrypt_fail — tampered CT, verify tag_ok=0

import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aes_gcm_driver import (
    AAD_BYTES,
    BLOCK_HEX_DIGITS,
    GEOMETRY_DESC,
    IV_BYTES,
    KEY_BYTES,
    NBLOCKS,
    PAYLOAD_BYTES,
    TAG_BYTES,
    AesGcmDriver,
    bytes_to_blocks,
    check_dut_geometry,
    op_cycles,
    pattern_bytes,
)

# ---------------------------------------------------------------------------
# Test vector geometry
# ---------------------------------------------------------------------------
CLK_NS    = 10             # 10 ns clock period
# One operation is bounded by op_cycles(); each test runs 5 vectors.
TIMEOUT_NS = 5 * op_cycles() * CLK_NS


# ---------------------------------------------------------------------------
# Test vectors
# ---------------------------------------------------------------------------

def _make_vectors():
    """Return list of (key, iv, aad, pt) as bytes objects, deterministic."""
    vecs = []

    # Vector 0 — all zeros
    vecs.append((
        bytes(KEY_BYTES),
        bytes(IV_BYTES),
        bytes(AAD_BYTES),
        bytes(PAYLOAD_BYTES),
    ))

    # Vector 1 — standard NIST-flavoured constants (FIPS-197 key for AES-256)
    vecs.append((
        bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c') if KEY_BYTES == 16 else
        bytes.fromhex('603deb1015ca71be2b73aef0857d7781'
                      '1f352c073b6108d72d9810a30914dff4'),
        bytes.fromhex('cafebabefacedbaddecaf888'),
        bytes.fromhex('feedfacedeadbeeffeedfacedeadbeef'),
        pattern_bytes(PAYLOAD_BYTES),
    ))

    # Vector 2 — all 0xFF
    vecs.append((
        bytes([0xFF] * KEY_BYTES),
        bytes([0xFF] * IV_BYTES),
        bytes([0xFF] * AAD_BYTES),
        bytes([0xFF] * PAYLOAD_BYTES),
    ))

    # Vector 3 — sequential, key=0x00..0x0F, iv=0x00..0x0B,
    #             aad=0x10..0x1F, payload starts at 0x20 and wraps.
    vecs.append((
        bytes(range(KEY_BYTES)),
        bytes(range(IV_BYTES)),
        bytes(range(0x10, 0x20)),
        pattern_bytes(PAYLOAD_BYTES, 0x20),
    ))

    # Vector 4 — seeded random
    rng = random.Random(42)
    vecs.append((
        rng.randbytes(KEY_BYTES),
        rng.randbytes(IV_BYTES),
        rng.randbytes(AAD_BYTES),
        rng.randbytes(PAYLOAD_BYTES),
    ))

    return vecs


VECTORS = _make_vectors()


# ---------------------------------------------------------------------------
# Reference model helpers
# ---------------------------------------------------------------------------

def ref_encrypt(key: bytes, iv: bytes, aad: bytes, pt: bytes):
    """Encrypt with Python AESGCM. Returns (ct_blocks, tag) as int lists."""
    raw = AESGCM(key).encrypt(iv, pt, aad)
    ct_raw, tag_raw = raw[:-TAG_BYTES], raw[-TAG_BYTES:]
    ct_blocks = bytes_to_blocks(ct_raw)
    tag = int.from_bytes(tag_raw, 'big')
    return ct_blocks, tag


def pt_to_blocks(pt: bytes) -> list:
    return bytes_to_blocks(pt)


def block_to_hex(v: int) -> str:
    return f'{v:0{BLOCK_HEX_DIGITS}x}'


# ---------------------------------------------------------------------------
# Clock setup helper
# ---------------------------------------------------------------------------

async def _setup(dut):
    """Start clock and return a fresh driver (does NOT call reset)."""
    cocotb.start_soon(Clock(dut.clk_i, CLK_NS, unit='ns').start())
    dut._log.info(f'Geometry: {GEOMETRY_DESC}')
    check_dut_geometry(dut)
    return AesGcmDriver(dut)


# ---------------------------------------------------------------------------
# Test 1: Encrypt KAT
# ---------------------------------------------------------------------------

@cocotb.test(timeout_time=TIMEOUT_NS * 4, timeout_unit='ns')
async def test_encrypt_kat(dut):
    """Encrypt 5 deterministic vectors, compare every CT block and tag."""
    drv = await _setup(dut)

    all_pass = True
    for vidx, (key, iv, aad, pt) in enumerate(VECTORS):
        exp_ct, exp_tag = ref_encrypt(key, iv, aad, pt)
        pt_blocks = pt_to_blocks(pt)

        await drv.reset()
        got_ct, got_tag = await drv.run_encrypt(
            int.from_bytes(key, 'big'),
            int.from_bytes(iv,  'big'),
            int.from_bytes(aad, 'big'),
            pt_blocks,
            ready_pattern=[
                [1],
                [0, 1],
                [1, 1, 0, 0, 1],
                [0, 0, 1, 1, 1],
                [1, 0, 1, 0, 0, 1],
            ][vidx],
            key_valid_delay=vidx % 3,
            aad_valid_delay=(vidx * 2) % 5,
            payload_gaps=[0, 1, 2],
        )

        vec_pass = True

        for blk_i in range(NBLOCKS):
            if got_ct[blk_i] != exp_ct[blk_i]:
                dut._log.error(
                    f'[v{vidx}] CT[{blk_i:02d}] MISMATCH\n'
                    f'  exp: {block_to_hex(exp_ct[blk_i])}\n'
                    f'  got: {block_to_hex(got_ct[blk_i])}'
                )
                vec_pass = False

        if got_tag != exp_tag:
            dut._log.error(
                f'[v{vidx}] TAG MISMATCH\n'
                f'  exp: {block_to_hex(exp_tag)}\n'
                f'  got: {block_to_hex(got_tag)}'
            )
            vec_pass = False

        if vec_pass:
            dut._log.info(f'[v{vidx}] encrypt PASS')
        else:
            all_pass = False

    assert all_pass, 'One or more encrypt vectors failed — see errors above'


# ---------------------------------------------------------------------------
# Test 2: Decrypt KAT
# ---------------------------------------------------------------------------

@cocotb.test(timeout_time=TIMEOUT_NS * 4, timeout_unit='ns')
async def test_decrypt_kat(dut):
    """
    For each vector: encrypt with RTL to get CT+tag, then decrypt with RTL,
    compare recovered PT against original plaintext, assert tag_ok=1.
    """
    drv = await _setup(dut)

    all_pass = True
    for vidx, (key, iv, aad, pt) in enumerate(VECTORS):
        exp_ct, exp_tag = ref_encrypt(key, iv, aad, pt)
        pt_blocks = pt_to_blocks(pt)

        key_i = int.from_bytes(key, 'big')
        iv_i  = int.from_bytes(iv,  'big')
        aad_i = int.from_bytes(aad, 'big')

        # Encrypt pass — use Python reference CT/tag so decrypt is independent
        # of any encrypt bug; keeps failures attributable to decrypt path alone.
        ct_blocks = exp_ct
        tag       = exp_tag

        await drv.reset()
        got_pt, tag_ok = await drv.run_decrypt(
            key_i, iv_i, aad_i, ct_blocks, tag,
            ready_pattern=[
                [1],
                [0, 1],
                [1, 0, 0, 1],
                [0, 0, 1],
                [1, 1, 0, 1, 0],
            ][vidx],
            key_valid_delay=vidx % 3,
            aad_valid_delay=(vidx * 2) % 5,
            payload_gaps=[2, 0, 1],
        )

        vec_pass = True

        for blk_i in range(NBLOCKS):
            if got_pt[blk_i] != pt_blocks[blk_i]:
                dut._log.error(
                    f'[v{vidx}] PT[{blk_i:02d}] MISMATCH\n'
                    f'  exp: {block_to_hex(pt_blocks[blk_i])}\n'
                    f'  got: {block_to_hex(got_pt[blk_i])}'
                )
                vec_pass = False

        if tag_ok != 1:
            dut._log.error(f'[v{vidx}] tag_ok_o = {tag_ok}, expected 1')
            vec_pass = False

        if vec_pass:
            dut._log.info(f'[v{vidx}] decrypt PASS')
        else:
            all_pass = False

    assert all_pass, 'One or more decrypt vectors failed — see errors above'


# ---------------------------------------------------------------------------
# Test 3: Decrypt-fail (tamper detection)
# ---------------------------------------------------------------------------

@cocotb.test(timeout_time=TIMEOUT_NS * 4, timeout_unit='ns')
async def test_decrypt_fail(dut):
    """
    For each vector: encrypt to get CT+tag, flip CT[0] bit 0, decrypt with
    the original tag — assert cipher_tag_ok_o == 0 (tamper detected).
    """
    drv = await _setup(dut)

    all_pass = True
    for vidx, (key, iv, aad, pt) in enumerate(VECTORS):
        exp_ct, exp_tag = ref_encrypt(key, iv, aad, pt)

        key_i = int.from_bytes(key, 'big')
        iv_i  = int.from_bytes(iv,  'big')
        aad_i = int.from_bytes(aad, 'big')

        # Tamper: flip bit 0 of CT block 0
        tampered = list(exp_ct)
        tampered[0] ^= 1

        await drv.reset()
        _, tag_ok = await drv.run_decrypt(
            key_i, iv_i, aad_i, tampered, exp_tag,
            ready_pattern=[
                [1],
                [0, 1],
                [1, 0, 1],
                [0, 0, 1, 1],
                [1, 1, 0, 0, 1],
            ][vidx],
            key_valid_delay=vidx % 3,
            aad_valid_delay=(vidx * 2) % 5,
            payload_gaps=[1, 2, 0],
        )

        if tag_ok != 0:
            dut._log.error(
                f'[v{vidx}] tamper NOT detected: tag_ok_o = {tag_ok}, expected 0'
            )
            all_pass = False
        else:
            dut._log.info(f'[v{vidx}] tamper-detect PASS (tag_ok_o=0)')

    assert all_pass, 'One or more tamper-detect checks failed — see errors above'
