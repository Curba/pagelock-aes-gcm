# AES-GCM configurable constrained-random test suite. Geometry-agnostic:
# key size and payload length come from aes_gcm_driver (environment).
# Reference model: Python cryptography.hazmat AESGCM.
# Author: Baris
# Date: 2026-06-02
#
# Structure:
#   TestScenario  — dataclass describing one test (category, label, op list)
#   make_op_*     — op-dict factory helpers
#   generate_scenarios(rng) — builds the full 1923-scenario pool
#   select_scenarios(...)   — selects a category-balanced configured subset

import os
import random
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

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
    SIM_NAME,
    TAG_BYTES,
    AesGcmDriver,
    bytes_to_blocks,
    check_dut_geometry,
    op_cycles,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CLK_NS   = 10
# Blocks driven before a mid-operation abandon (category 9)
INTERRUPT_BLOCKS = max(1, NBLOCKS // 2)
FULL_SCENARIO_COUNT = 1923
DEFAULT_SCENARIO_COUNT = 128
DEFAULT_SEED = 2026

RANDOM_COUNT = int(os.getenv('AES_RANDOM_COUNT', DEFAULT_SCENARIO_COUNT))
RANDOM_SEED = int(os.getenv('AES_RANDOM_SEED', DEFAULT_SEED))

# ---------------------------------------------------------------------------
# Category descriptions (used in report)
# ---------------------------------------------------------------------------

CATEGORY_DESC = {
    'encrypt_only':       'Single encrypt, random inputs, CT+tag vs reference',
    'enc_dec_roundtrip':  'Encrypt then decrypt (with reset), verify PT recovery + tag_ok',
    'enc_dec_no_reset':   'Encrypt then decrypt (no reset), verify internal state cleanup',
    'interleaved':        'Encrypt A, encrypt B, decrypt A — stale state detection',
    'back2back_enc':      'Three consecutive encrypts without reset',
    'key_reuse':          'Two encrypts sharing a key, different IV/AAD/PT',
    'determinism':        'Identical inputs twice — assert identical outputs',
    'corner_cases':       'Single-bit-set key/IV/AAD sweeps (bits 0-40)',
    'reset_recovery':     'Mid-operation reset (half the blocks), then clean operation',
    'complementary':      'Encrypt P then ~P with same key/IV/AAD',
}

try:
    from cocotb.utils import get_sim_time as _get_sim_time
except ImportError:
    _get_sim_time = None


# ---------------------------------------------------------------------------
# TestScenario dataclass
# ---------------------------------------------------------------------------

@dataclass
class TestScenario:
    category: str        # one of the 10 category names
    label: str           # human-readable, e.g. "enc_only_0042"
    ops: list[dict] = field(default_factory=list)
    check_determinism: bool = False  # cat 7: assert op0 and op1 produce identical CT+tag
    # Each element of ops is a dict with keys:
    #   mode: "encrypt" | "decrypt"
    #   key: bytes (16)
    #   iv: bytes (12)
    #   aad: bytes (16)
    #   pt: bytes (PAYLOAD_BYTES) — plaintext (encrypt source / decrypt oracle)
    #   ct_blocks: list[int]|None — CT to feed on decrypt (filled at runtime)
    #   exp_tag: int|None         — expected tag on decrypt (filled at runtime)
    #   reset_before: bool
    #   check_ct: bool            — compare CT output against ref
    #   check_pt: bool            — compare PT output against original
    #   check_tag_ok: bool        — assert tag_ok_o == 1
    #   check_tag_reject: bool    — assert tag_ok_o == 0


# ---------------------------------------------------------------------------
# Op-dict factory helpers
# ---------------------------------------------------------------------------

def make_op_encrypt(
    key: bytes,
    iv: bytes,
    aad: bytes,
    pt: bytes,
    reset_before: bool = True,
) -> dict:
    """Return an encrypt op dict with CT-comparison enabled."""
    return {
        'mode':          'encrypt',
        'key':           key,
        'iv':            iv,
        'aad':           aad,
        'pt':            pt,
        'ct_blocks':     None,
        'exp_tag':       None,
        'reset_before':  reset_before,
        'check_ct':      True,
        'check_pt':      False,
        'check_tag_ok':  False,
        'check_tag_reject': False,
    }


def make_op_decrypt(
    key: bytes,
    iv: bytes,
    aad: bytes,
    pt: bytes,
    reset_before: bool = True,
) -> dict:
    """
    Return a decrypt op dict with PT-comparison and tag_ok assertion enabled.
    ct_blocks and exp_tag are None here; the runner fills them from a prior
    encrypt's RTL output or from the Python reference before executing.
    """
    return {
        'mode':          'decrypt',
        'key':           key,
        'iv':            iv,
        'aad':           aad,
        'pt':            pt,
        'ct_blocks':     None,   # filled at runtime
        'exp_tag':       None,   # filled at runtime
        'reset_before':  reset_before,
        'check_ct':      False,
        'check_pt':      True,
        'check_tag_ok':  True,
        'check_tag_reject': False,
    }


# ---------------------------------------------------------------------------
# Scenario generator
# ---------------------------------------------------------------------------

def rand_bytes(rng: random.Random, n: int) -> bytes:
    return rng.randbytes(n)


def _gen_encrypt_only(rng: random.Random) -> list[TestScenario]:
    """Category 1 — 600 single-encrypt scenarios."""
    scenarios = []
    for i in range(600):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        scenarios.append(TestScenario(
            category='encrypt_only',
            label=f'enc_only_{i:04d}',
            ops=[make_op_encrypt(key, iv, aad, pt, reset_before=True)],
        ))
    return scenarios


def _gen_enc_dec_roundtrip(rng: random.Random) -> list[TestScenario]:
    """
    Category 2 — 400 encrypt-then-decrypt roundtrip scenarios.
    op1 carries use_ref_ct=True so the runner fills ct_blocks/exp_tag from
    the Python reference rather than the RTL output, keeping decrypt failures
    independent of any encrypt bug.
    """
    scenarios = []
    for i in range(400):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        op_enc = make_op_encrypt(key, iv, aad, pt, reset_before=True)
        op_dec = make_op_decrypt(key, iv, aad, pt, reset_before=True)
        op_dec['use_ref_ct'] = True
        scenarios.append(TestScenario(
            category='enc_dec_roundtrip',
            label=f'enc_dec_rt_{i:04d}',
            ops=[op_enc, op_dec],
        ))
    return scenarios


def _gen_enc_dec_no_reset(rng: random.Random) -> list[TestScenario]:
    """
    Category 3 — 150 roundtrip scenarios where decrypt runs without a reset
    between encrypt and decrypt (op1 reset_before=False).
    """
    scenarios = []
    for i in range(150):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        op_enc = make_op_encrypt(key, iv, aad, pt, reset_before=True)
        op_dec = make_op_decrypt(key, iv, aad, pt, reset_before=False)
        op_dec['use_ref_ct'] = True
        scenarios.append(TestScenario(
            category='enc_dec_no_reset',
            label=f'enc_dec_norst_{i:04d}',
            ops=[op_enc, op_dec],
        ))
    return scenarios


def _gen_interleaved(rng: random.Random) -> list[TestScenario]:
    """
    Category 4 — 200 interleaved scenarios.
    op0: encrypt A (reset_before=True,  check_ct=True)
    op1: encrypt B (reset_before=False, check_ct=True)
    op2: decrypt A (reset_before=False, check_pt=True, check_tag_ok=True,
                    use_ref_ct=True)
    Exercises that stale state from op1 does not corrupt op2's A result.
    """
    scenarios = []
    for i in range(200):
        key_a = rand_bytes(rng, KEY_BYTES)
        iv_a  = rand_bytes(rng, IV_BYTES)
        aad_a = rand_bytes(rng, AAD_BYTES)
        pt_a  = rand_bytes(rng, PAYLOAD_BYTES)

        key_b = rand_bytes(rng, KEY_BYTES)
        iv_b  = rand_bytes(rng, IV_BYTES)
        aad_b = rand_bytes(rng, AAD_BYTES)
        pt_b  = rand_bytes(rng, PAYLOAD_BYTES)

        op0 = make_op_encrypt(key_a, iv_a, aad_a, pt_a, reset_before=True)
        op1 = make_op_encrypt(key_b, iv_b, aad_b, pt_b, reset_before=False)
        op2 = make_op_decrypt(key_a, iv_a, aad_a, pt_a, reset_before=False)
        op2['use_ref_ct'] = True

        scenarios.append(TestScenario(
            category='interleaved',
            label=f'interleaved_{i:04d}',
            ops=[op0, op1, op2],
        ))
    return scenarios


def _gen_back2back_enc(rng: random.Random) -> list[TestScenario]:
    """
    Category 5 — 100 back-to-back encrypt scenarios.
    Three encrypts with distinct random params; only op0 resets, op1/op2 do not.
    All three ops check CT against the reference.
    """
    scenarios = []
    for i in range(100):
        ops = []
        for j in range(3):
            key = rand_bytes(rng, KEY_BYTES)
            iv  = rand_bytes(rng, IV_BYTES)
            aad = rand_bytes(rng, AAD_BYTES)
            pt  = rand_bytes(rng, PAYLOAD_BYTES)
            ops.append(make_op_encrypt(key, iv, aad, pt, reset_before=(j == 0)))
        scenarios.append(TestScenario(
            category='back2back_enc',
            label=f'back2back_{i:04d}',
            ops=ops,
        ))
    return scenarios


def _gen_key_reuse(rng: random.Random) -> list[TestScenario]:
    """
    Category 6 — 100 key-reuse scenarios.
    Two encrypts share the same key but use distinct random IV/AAD/PT.
    op0 resets; op1 does not (back-to-back, same key).
    """
    scenarios = []
    for i in range(100):
        key   = rand_bytes(rng, KEY_BYTES)
        iv_a  = rand_bytes(rng, IV_BYTES)
        aad_a = rand_bytes(rng, AAD_BYTES)
        pt_a  = rand_bytes(rng, PAYLOAD_BYTES)
        iv_b  = rand_bytes(rng, IV_BYTES)
        aad_b = rand_bytes(rng, AAD_BYTES)
        pt_b  = rand_bytes(rng, PAYLOAD_BYTES)
        scenarios.append(TestScenario(
            category='key_reuse',
            label=f'key_reuse_{i:04d}',
            ops=[
                make_op_encrypt(key, iv_a, aad_a, pt_a, reset_before=True),
                make_op_encrypt(key, iv_b, aad_b, pt_b, reset_before=False),
            ],
        ))
    return scenarios


def _gen_determinism(rng: random.Random) -> list[TestScenario]:
    """
    Category 7 — 50 determinism scenarios.
    Two encrypts with identical key/IV/AAD/PT; both reset_before=True.
    check_determinism=True instructs the runner to assert identical CT+tag.
    """
    scenarios = []
    for i in range(50):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        scenarios.append(TestScenario(
            category='determinism',
            label=f'determinism_{i:04d}',
            check_determinism=True,
            ops=[
                make_op_encrypt(key, iv, aad, pt, reset_before=True),
                make_op_encrypt(key, iv, aad, pt, reset_before=True),
            ],
        ))
    return scenarios


def _gen_corner_cases(rng: random.Random) -> list[TestScenario]:
    """
    Category 8 — 123 corner-case scenarios (41 per sub-group).
    a) Single-bit-set key,  bits 0..40 — random IV/AAD/PT.
    b) Single-bit-set IV,   bits 0..40 — random key/AAD/PT.
    c) Single-bit-set AAD,  bits 0..40 — random key/IV/PT.
    Each scenario has 1 encrypt op, check_ct=True.
    """
    scenarios = []
    for bit in range(41):
        # sub-group a: single-bit key
        key = (1 << bit).to_bytes(KEY_BYTES, 'big')
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        scenarios.append(TestScenario(
            category='corner_cases',
            label=f'corner_key_{bit:03d}',
            ops=[make_op_encrypt(key, iv, aad, pt, reset_before=True)],
        ))

        # sub-group b: single-bit IV
        key = rand_bytes(rng, KEY_BYTES)
        iv  = (1 << bit).to_bytes(IV_BYTES, 'big')
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        scenarios.append(TestScenario(
            category='corner_cases',
            label=f'corner_iv_{bit:03d}',
            ops=[make_op_encrypt(key, iv, aad, pt, reset_before=True)],
        ))

        # sub-group c: single-bit AAD
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = (1 << bit).to_bytes(AAD_BYTES, 'big')
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        scenarios.append(TestScenario(
            category='corner_cases',
            label=f'corner_aad_{bit:03d}',
            ops=[make_op_encrypt(key, iv, aad, pt, reset_before=True)],
        ))

    return scenarios


def _gen_reset_recovery(rng: random.Random) -> list[TestScenario]:
    """
    Category 9 — 100 reset-recovery scenarios.
    op0: encrypt that the runner interrupts after INTERRUPT_BLOCKS blocks.
         reset_before=True, check_ct=False (output is discarded).
    op1: clean encrypt with different params, reset_before=True, check_ct=True.
    Verifies the FSM recovers correctly after a mid-operation reset.
    """
    scenarios = []
    for i in range(100):
        key_a = rand_bytes(rng, KEY_BYTES)
        iv_a  = rand_bytes(rng, IV_BYTES)
        aad_a = rand_bytes(rng, AAD_BYTES)
        pt_a  = rand_bytes(rng, PAYLOAD_BYTES)

        key_b = rand_bytes(rng, KEY_BYTES)
        iv_b  = rand_bytes(rng, IV_BYTES)
        aad_b = rand_bytes(rng, AAD_BYTES)
        pt_b  = rand_bytes(rng, PAYLOAD_BYTES)

        op0 = make_op_encrypt(key_a, iv_a, aad_a, pt_a, reset_before=True)
        op0['check_ct']             = False
        op0['interrupt_after_blocks'] = INTERRUPT_BLOCKS

        op1 = make_op_encrypt(key_b, iv_b, aad_b, pt_b, reset_before=True)

        scenarios.append(TestScenario(
            category='reset_recovery',
            label=f'reset_recv_{i:04d}',
            ops=[op0, op1],
        ))
    return scenarios


def _gen_complementary(rng: random.Random) -> list[TestScenario]:
    """
    Category 10 — 100 complementary-plaintext scenarios.
    Two encrypts with the same key/IV/AAD but PT and ~PT (bitwise complement).
    Both reset_before=True, both check_ct=True.
    """
    scenarios = []
    for i in range(100):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        pt_comp = bytes(b ^ 0xFF for b in pt)
        scenarios.append(TestScenario(
            category='complementary',
            label=f'complement_{i:04d}',
            ops=[
                make_op_encrypt(key, iv, aad, pt,      reset_before=True),
                make_op_encrypt(key, iv, aad, pt_comp, reset_before=True),
            ],
        ))
    return scenarios


def generate_scenarios(rng: random.Random) -> list[TestScenario]:
    scenarios: list[TestScenario] = []
    scenarios.extend(_gen_encrypt_only(rng))       # 600
    scenarios.extend(_gen_enc_dec_roundtrip(rng))  # 400
    scenarios.extend(_gen_enc_dec_no_reset(rng))   # 150
    scenarios.extend(_gen_interleaved(rng))        # 200
    scenarios.extend(_gen_back2back_enc(rng))      # 100
    scenarios.extend(_gen_key_reuse(rng))          # 100
    scenarios.extend(_gen_determinism(rng))        #  50
    scenarios.extend(_gen_corner_cases(rng))       # 123
    scenarios.extend(_gen_reset_recovery(rng))     # 100
    scenarios.extend(_gen_complementary(rng))      # 100
    assert len(scenarios) == FULL_SCENARIO_COUNT, (
        f'Expected {FULL_SCENARIO_COUNT} scenarios, got {len(scenarios)}'
    )
    return scenarios


def select_scenarios(
    scenarios: list[TestScenario],
    count: int,
    rng: random.Random,
) -> list[TestScenario]:
    """Select a shuffled, category-balanced subset from the full pool."""
    assert 1 <= count <= len(scenarios), (
        f'AES_RANDOM_COUNT must be in [1, {len(scenarios)}], got {count}'
    )
    if count == len(scenarios):
        return scenarios

    by_category: dict[str, list[TestScenario]] = {}
    for scenario in scenarios:
        by_category.setdefault(scenario.category, []).append(scenario)
    for entries in by_category.values():
        rng.shuffle(entries)

    selected = []
    categories = list(by_category)
    while len(selected) < count:
        made_progress = False
        for category in categories:
            entries = by_category[category]
            if entries and len(selected) < count:
                selected.append(entries.pop())
                made_progress = True
        if not made_progress:
            break

    rng.shuffle(selected)
    return selected


# ---------------------------------------------------------------------------
# Module-level scenario list
# ---------------------------------------------------------------------------

_selection_rng = random.Random(RANDOM_SEED)
_scenario_pool = generate_scenarios(random.Random(RANDOM_SEED))
SCENARIOS = select_scenarios(_scenario_pool, RANDOM_COUNT, _selection_rng)


# ---------------------------------------------------------------------------
# Reference-model helpers
# ---------------------------------------------------------------------------

def ref_encrypt(key: bytes, iv: bytes, aad: bytes, pt: bytes):
    """Encrypt with Python AESGCM. Returns (ct_blocks, tag) as (list[int], int)."""
    raw = AESGCM(key).encrypt(iv, pt, aad)
    ct_raw, tag_raw = raw[:-TAG_BYTES], raw[-TAG_BYTES:]
    ct_blocks = bytes_to_blocks(ct_raw)
    return ct_blocks, int.from_bytes(tag_raw, 'big')


def pt_to_blocks(pt: bytes) -> list:
    return bytes_to_blocks(pt)


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

@cocotb.test(timeout_time=max(25 * 60 * 1_000_000_000,
                              4 * RANDOM_COUNT * op_cycles() * CLK_NS),
             timeout_unit='ns')
async def test_random_suite(dut):
    """
    Execute the configured constrained-random scenario subset.
    Each scenario's ops are run in order; results are collected per category,
    then a full summary is printed and the configured total is asserted.
    """
    cocotb.start_soon(Clock(dut.clk_i, CLK_NS, unit='ns').start())
    dut._log.info(f'Geometry: {GEOMETRY_DESC}')
    check_dut_geometry(dut)
    drv = AesGcmDriver(dut)
    traffic_rng = random.Random(RANDOM_SEED ^ 0xA5E5_6C3D)

    # results[category] = list of (label, passed: bool, first_failure_detail: str|None)
    results: dict[str, list] = {}
    for s in SCENARIOS:
        if s.category not in results:
            results[s.category] = []

    for s_idx, scenario in enumerate(SCENARIOS):
        if s_idx % max(1, RANDOM_COUNT // 10) == 0:
            dut._log.info(f'Progress: {s_idx}/{RANDOM_COUNT}')

        scenario_failure_details: list[dict] = []
        # op_outputs[i] = (ct_or_pt_blocks: list[int], tag_or_tag_ok: int)
        #               or None for interrupted ops (category 9 op0)
        op_outputs: list = []
        # Updated after each completed encrypt for non-use_ref_ct decrypts
        last_enc_ct:  list[int] | None = None
        last_enc_tag: int       | None = None

        for op_idx, op in enumerate(scenario.ops):
            interrupt_n = op.get('interrupt_after_blocks')

            # ------------------------------------------------------------------
            # Category 9: interrupted encrypt — drive partial blocks then abandon
            # ------------------------------------------------------------------
            if interrupt_n is not None:
                if op['reset_before']:
                    await drv.reset()
                key_i = int.from_bytes(op['key'], 'big')
                iv_i  = int.from_bytes(op['iv'],  'big')
                aad_i = int.from_bytes(op['aad'], 'big')
                pt_blks = pt_to_blocks(op['pt'])
                await drv._start_operation(mode=1, key=key_i, iv=iv_i, aad=aad_i)
                await drv._drive_payload(pt_blks[:interrupt_n])
                # Leave FSM mid-flight; next op's reset_before=True cleans up.
                op_outputs.append(None)
                continue

            # ------------------------------------------------------------------
            # Normal op
            # ------------------------------------------------------------------
            if op['reset_before']:
                await drv.reset()

            key_i   = int.from_bytes(op['key'], 'big')
            iv_i    = int.from_bytes(op['iv'],  'big')
            aad_i   = int.from_bytes(op['aad'], 'big')
            pt_blks = pt_to_blocks(op['pt'])
            ref_ct, ref_tag = ref_encrypt(op['key'], op['iv'], op['aad'], op['pt'])
            ready_pattern = [
                traffic_rng.randint(0, 1)
                for _ in range(traffic_rng.randint(3, 8))
            ]
            if not any(ready_pattern):
                ready_pattern[-1] = 1
            key_valid_delay = traffic_rng.randint(0, 2)
            aad_valid_delay = traffic_rng.randint(0, 4)
            payload_gaps = [
                traffic_rng.randint(0, 2)
                for _ in range(traffic_rng.randint(1, 4))
            ]

            if op['mode'] == 'encrypt':
                got_ct, got_tag = await drv.run_encrypt(
                    key_i,
                    iv_i,
                    aad_i,
                    pt_blks,
                    ready_pattern=ready_pattern,
                    key_valid_delay=key_valid_delay,
                    aad_valid_delay=aad_valid_delay,
                    payload_gaps=payload_gaps,
                )
                op_outputs.append((got_ct, got_tag))
                last_enc_ct  = got_ct
                last_enc_tag = got_tag

                if op['check_ct']:
                    for blk_i in range(NBLOCKS):
                        if got_ct[blk_i] != ref_ct[blk_i]:
                            scenario_failure_details.append({
                                'op_idx': op_idx, 'op_mode': 'encrypt',
                                'key': op['key'], 'iv': op['iv'], 'aad': op['aad'],
                                'pt_first_block': pt_blks[0], 'pt_last_block': pt_blks[-1],
                                'field': f'CT[{blk_i:02d}]',
                                'expected': ref_ct[blk_i], 'got': got_ct[blk_i],
                            })
                            break
                    if got_tag != ref_tag:
                        scenario_failure_details.append({
                            'op_idx': op_idx, 'op_mode': 'encrypt',
                            'key': op['key'], 'iv': op['iv'], 'aad': op['aad'],
                            'pt_first_block': pt_blks[0], 'pt_last_block': pt_blks[-1],
                            'field': 'TAG',
                            'expected': ref_tag, 'got': got_tag,
                        })

            else:  # decrypt
                if op.get('use_ref_ct'):
                    ct_feed  = ref_ct
                    tag_feed = ref_tag
                else:
                    # Fall back to the most recent encrypt output in this scenario
                    ct_feed  = last_enc_ct
                    tag_feed = last_enc_tag

                got_pt, tag_ok = await drv.run_decrypt(
                    key_i,
                    iv_i,
                    aad_i,
                    ct_feed,
                    tag_feed,
                    ready_pattern=ready_pattern,
                    key_valid_delay=key_valid_delay,
                    aad_valid_delay=aad_valid_delay,
                    payload_gaps=payload_gaps,
                )
                op_outputs.append((got_pt, tag_ok))

                if op['check_pt']:
                    for blk_i in range(NBLOCKS):
                        if got_pt[blk_i] != pt_blks[blk_i]:
                            scenario_failure_details.append({
                                'op_idx': op_idx, 'op_mode': 'decrypt',
                                'key': op['key'], 'iv': op['iv'], 'aad': op['aad'],
                                'pt_first_block': pt_blks[0], 'pt_last_block': pt_blks[-1],
                                'field': f'PT[{blk_i:02d}]',
                                'expected': pt_blks[blk_i], 'got': got_pt[blk_i],
                            })
                            break

                if op['check_tag_ok'] and tag_ok != 1:
                    scenario_failure_details.append({
                        'op_idx': op_idx, 'op_mode': 'decrypt',
                        'key': op['key'], 'iv': op['iv'], 'aad': op['aad'],
                        'pt_first_block': pt_blks[0], 'pt_last_block': pt_blks[-1],
                        'field': 'tag_ok', 'expected': 1, 'got': tag_ok,
                    })

                if op['check_tag_reject'] and tag_ok != 0:
                    scenario_failure_details.append({
                        'op_idx': op_idx, 'op_mode': 'decrypt',
                        'key': op['key'], 'iv': op['iv'], 'aad': op['aad'],
                        'pt_first_block': pt_blks[0], 'pt_last_block': pt_blks[-1],
                        'field': 'tag_ok', 'expected': 0, 'got': tag_ok,
                    })

        # ------------------------------------------------------------------
        # Determinism check (category 7): op0 and op1 must match exactly
        # ------------------------------------------------------------------
        if scenario.check_determinism:
            out0, out1 = op_outputs[0], op_outputs[1]
            if out0 is not None and out1 is not None:
                ct0, tag0 = out0
                ct1, tag1 = out1
                det_op  = scenario.ops[0]
                det_pt  = pt_to_blocks(det_op['pt'])
                for blk_i in range(NBLOCKS):
                    if ct0[blk_i] != ct1[blk_i]:
                        scenario_failure_details.append({
                            'op_idx': 0, 'op_mode': 'encrypt',
                            'key': det_op['key'], 'iv': det_op['iv'], 'aad': det_op['aad'],
                            'pt_first_block': det_pt[0], 'pt_last_block': det_pt[-1],
                            'field': f'DETERMINISM CT[{blk_i:02d}]',
                            'expected': ct0[blk_i], 'got': ct1[blk_i],
                        })
                        break
                if tag0 != tag1:
                    scenario_failure_details.append({
                        'op_idx': 0, 'op_mode': 'encrypt',
                        'key': det_op['key'], 'iv': det_op['iv'], 'aad': det_op['aad'],
                        'pt_first_block': det_pt[0], 'pt_last_block': det_pt[-1],
                        'field': 'DETERMINISM TAG',
                        'expected': tag0, 'got': tag1,
                    })

        passed = not scenario_failure_details
        results[scenario.category].append((scenario.label, passed, scenario_failure_details))

    # ------------------------------------------------------------------
    # Tally results
    # ------------------------------------------------------------------
    total_passed      = 0
    total_ops         = sum(len(s.ops) for s in SCENARIOS)
    all_failed_labels: list[str] = []

    # ops-per-category (first scenario for each category is representative)
    cat_ops_count: dict[str, int] = {}
    for s in SCENARIOS:
        if s.category not in cat_ops_count:
            cat_ops_count[s.category] = len(s.ops)

    for category, entries in results.items():
        cat_pass  = sum(1 for _, p, _ in entries if p)
        cat_total = len(entries)
        total_passed += cat_pass
        dut._log.info(f'{category}: {cat_pass}/{cat_total}')
        for label, passed, _ in entries:
            if not passed:
                all_failed_labels.append(label)

    total_failed = RANDOM_COUNT - total_passed
    dut._log.info(
        f'TOTAL: {total_passed}/{RANDOM_COUNT} — {total_failed} failure(s)'
    )

    # ------------------------------------------------------------------
    # Report file
    # ------------------------------------------------------------------
    report_path = (
        Path(__file__).resolve().parents[2]
        / 'build' / 'reports'
        / f'report_random_suite_k{KEY_BYTES * 8}_p{PAYLOAD_BYTES + 32}.txt'
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    SEP_HEAVY   = '═' * 56
    SEP_LIGHT   = '─' * 56

    try:
        sim_ns = _get_sim_time('ns') if _get_sim_time else None
        sim_time_str = f'{sim_ns:.0f} ns' if sim_ns is not None else 'N/A'
    except Exception:
        sim_time_str = 'N/A'

    with report_path.open('w') as rpt:
        def w(line=''):
            rpt.write(line + '\n')

        w(SEP_HEAVY)
        w(f'AES-{KEY_BYTES * 8}-GCM Constrained-Random Verification Report')
        w(SEP_HEAVY)
        w(f'Date:       {datetime.now().isoformat()}')
        w(f'Seed:       {RANDOM_SEED}')
        w(f'Simulator:  {SIM_NAME} (cocotb)')
        w(f'Geometry:   {GEOMETRY_DESC}')
        w(SEP_LIGHT)
        w(f'Scenarios:  {RANDOM_COUNT}')
        w(f'Operations: {total_ops}')
        w(f'Passed:     {total_passed}/{RANDOM_COUNT}')
        w(f'Failed:     {total_failed}/{RANDOM_COUNT}')
        w(f'Sim time:   {sim_time_str}')
        w(SEP_LIGHT)
        w()

        for category, entries in results.items():
            cat_pass  = sum(1 for _, p, _ in entries if p)
            cat_total = len(entries)
            cat_fail  = cat_total - cat_pass

            w(f'═══ {category} ═══ {cat_pass}/{cat_total} ═══')
            w(f'Description:  {CATEGORY_DESC.get(category, "")}')
            w(f'Ops/scenario: {cat_ops_count.get(category, "?")}')

            if cat_fail == 0:
                w(f'All {cat_total} scenarios passed.')
            else:
                fail_entries = [
                    (lbl, dets)
                    for lbl, ok, dets in entries
                    if not ok and dets
                ]
                for label, failure_details in fail_entries[:5]:
                    fd = failure_details[0]
                    w(f'FAIL {label}')
                    w(f'  Key: {fd["key"].hex()}')
                    w(f'  IV:  {fd["iv"].hex()}')
                    w(f'  AAD: {fd["aad"].hex()}')
                    w(
                        f'  PT:  '
                        f'{fd["pt_first_block"]:0{BLOCK_HEX_DIGITS}x}...'
                        f'{fd["pt_last_block"]:0{BLOCK_HEX_DIGITS}x} '
                        f'({PAYLOAD_BYTES} B)'
                    )
                    w(f'  Op:  {fd["op_mode"]}, index {fd["op_idx"]}')
                    w(
                        f'  Expected {fd["field"]}: '
                        f'{fd["expected"]:0{BLOCK_HEX_DIGITS}x}'
                    )
                    w(
                        f'  Got      {fd["field"]}: '
                        f'{fd["got"]:0{BLOCK_HEX_DIGITS}x}'
                    )
                if len(fail_entries) > 5:
                    w(f'... and {len(fail_entries) - 5} more')
            w()

        if all_failed_labels:
            w(SEP_HEAVY)
            w(f'FAILURE SUMMARY — {total_failed} scenario(s)')
            w(SEP_HEAVY)
            for lbl in all_failed_labels:
                w(f'  {lbl}')
            w()

        w(SEP_HEAVY)
        if total_failed == 0:
            w(f'VERDICT: ALL {RANDOM_COUNT} SCENARIOS PASSED')
        else:
            w(f'VERDICT: {total_failed} FAILURE(S)')
        w(SEP_HEAVY)

    dut._log.info(f'Report written to {report_path}')

    assert total_passed == RANDOM_COUNT, (
        f'Random suite: {total_failed} failure(s) — see report_random_suite.txt'
    )
