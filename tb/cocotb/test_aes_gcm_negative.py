# AES-GCM negative and robustness suite (100 directed scenarios).
# Geometry-agnostic: key size, payload length and watchdog threshold come
# from aes_gcm_driver (environment).
# Reference model: Python cryptography.hazmat AESGCM.
# Author: Baris
# Date: 2026-06-02
#
# Structure:
#   TestScenario  — dataclass describing one test (category, label, op list)
#   make_op_*     — op-dict factory helpers (encrypt / decrypt)
#   generate_negative_scenarios(rng) — builds scenario list (cats 1-5 here)
#   test_negative_suite             — cocotb entry point (placeholder)
#
# Op dict special keys (beyond the base set from aes_gcm_driver):
#   special_action: str|None — "start_mid_op", "double_start",
#                              "early_valid", "watchdog_starve", None

import random
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer
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
    SPI_POISON,
    TAG_BYTES,
    WDT_TIMEOUT,
    AesGcmDriver,
    bytes_to_blocks,
    check_dut_geometry,
    op_cycles,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CLK_NS   = 10
# Blocks driven before the mid-operation start_i injection (>= 0, < NBLOCKS)
MID_OP_BLOCKS = NBLOCKS // 2
# Starve time for the watchdog scenario: the counter runs from command accept,
# so WDT_TIMEOUT cycles plus a small margin guarantees the abort has fired.
WDT_STARVE_NS = (WDT_TIMEOUT + 200) * CLK_NS

# ---------------------------------------------------------------------------
# Category descriptions
# ---------------------------------------------------------------------------

CATEGORY_DESC = {
    'tamper_aad':     'Decrypt with corrupted AAD — tag rejection',
    'tamper_tag':     'Decrypt with corrupted exp_tag_i — tag rejection',
    'tamper_ct':      'Decrypt with corrupted first/middle/last CT block — tag rejection',
    'tamper_iv':      'Decrypt with corrupted IV — tag rejection',
    'tamper_key':     'Decrypt with corrupted key — tag rejection',
    'mode_switching': 'Back-to-back mode changes (enc/dec/enc) without reset',
    'start_mid_op':   'Pulse start_i during ST_PROC_PAYLOAD — must be ignored',
    'double_start':   'Two-cycle start_i pulse — must not double-init',
    'early_valid':    'Assert data_in_valid before FSM ready — must be ignored',
    'watchdog':       'Starve payload, verify err_o + recovery',
    'reset_timing':   'Reset held 1/2/4/8 cycles, verify clean operation',
    'same_key_burst': 'N encrypts same key, no resets',
    'zeros_exp_tag':  'Decrypt with exp_tag_i=0 — must reject',
}

# ---------------------------------------------------------------------------
# TestScenario dataclass
# ---------------------------------------------------------------------------

@dataclass
class TestScenario:
    category: str
    label: str
    ops: list[dict] = field(default_factory=list)
    trace: str = ''
    check_determinism: bool = False
    reset_cycles: int = 4
    # Op dict keys:
    #   mode: "encrypt" | "decrypt"
    #   key, iv, aad, pt: bytes
    #   ct_blocks: list[int]|None  — pre-filled CT for decrypt; None = computed at runtime
    #   exp_tag: int|None          — pre-filled tag for decrypt; None = computed at runtime
    #   reset_before: bool
    #   check_ct: bool
    #   check_pt: bool
    #   check_tag_ok: bool
    #   check_tag_reject: bool
    #   use_ref_ct: bool           — True: runner fills ct/tag from Python ref
    #   special_action: str|None

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
    return {
        'mode':           'encrypt',
        'key':            key,
        'iv':             iv,
        'aad':            aad,
        'pt':             pt,
        'ct_blocks':      None,
        'exp_tag':        None,
        'reset_before':   reset_before,
        'check_ct':       True,
        'check_pt':       False,
        'check_tag_ok':   False,
        'check_tag_reject': False,
        'use_ref_ct':     False,
        'special_action': None,
    }


def make_op_decrypt(
    key: bytes,
    iv: bytes,
    aad: bytes,
    pt: bytes,
    reset_before: bool = True,
) -> dict:
    return {
        'mode':           'decrypt',
        'key':            key,
        'iv':             iv,
        'aad':            aad,
        'pt':             pt,
        'ct_blocks':      None,
        'exp_tag':        None,
        'reset_before':   reset_before,
        'check_ct':       False,
        'check_pt':       True,
        'check_tag_ok':   True,
        'check_tag_reject': False,
        'use_ref_ct':     True,
        'special_action': None,
    }


def _make_op_decrypt_prefilled(
    key: bytes,
    iv: bytes,
    aad: bytes,
    pt: bytes,
    ct_blocks: list,
    exp_tag: int,
    reset_before: bool = True,
    check_pt: bool = False,
    check_tag_ok: bool = False,
    check_tag_reject: bool = False,
) -> dict:
    """Decrypt op with CT and tag already computed (no runtime ref lookup)."""
    return {
        'mode':           'decrypt',
        'key':            key,
        'iv':             iv,
        'aad':            aad,
        'pt':             pt,
        'ct_blocks':      ct_blocks,
        'exp_tag':        exp_tag,
        'reset_before':   reset_before,
        'check_ct':       False,
        'check_pt':       check_pt,
        'check_tag_ok':   check_tag_ok,
        'check_tag_reject': check_tag_reject,
        'use_ref_ct':     False,
        'special_action': None,
    }

# ---------------------------------------------------------------------------
# Master RNG
# ---------------------------------------------------------------------------

rng = random.Random(7777)

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


def rand_bytes(rng: random.Random, n: int) -> bytes:
    return rng.randbytes(n)

# ---------------------------------------------------------------------------
# Category 1 — tamper_aad (10 scenarios)
# ---------------------------------------------------------------------------

def _gen_tamper_aad(rng: random.Random) -> list[TestScenario]:
    """
    op0: encrypt with random params.
    op1: decrypt with same key/iv/pt and same CT, but MODIFIED aad.
         check_tag_reject=True — GHASH over wrong AAD must cause tag mismatch.
    """
    scenarios = []
    for i in range(10):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)

        aad_int = int.from_bytes(aad, 'big')
        if i == 0:
            bad_aad = (aad_int ^ (1 << 0)).to_bytes(AAD_BYTES, 'big')
            trace = 'AAD bit 0 flipped; expect tag_ok=0'
        elif i == 1:
            bad_aad = (
                aad_int ^ (1 << ((AAD_BYTES * 8) // 2 - 1))
            ).to_bytes(AAD_BYTES, 'big')
            trace = f'AAD bit {(AAD_BYTES * 8) // 2 - 1} flipped; expect tag_ok=0'
        elif i == 2:
            bad_aad = (
                aad_int ^ (1 << (AAD_BYTES * 8 - 1))
            ).to_bytes(AAD_BYTES, 'big')
            trace = f'AAD bit {AAD_BYTES * 8 - 1} flipped; expect tag_ok=0'
        elif i == 3:
            bad_aad = bytes(AAD_BYTES)
            trace = 'AAD replaced with all zeros; expect tag_ok=0'
        elif i == 4:
            bad_aad = bytes([0xFF] * AAD_BYTES)
            trace = 'AAD replaced with all ones; expect tag_ok=0'
        else:
            bad_aad = rand_bytes(rng, AAD_BYTES)
            while bad_aad == aad:
                bad_aad = rand_bytes(rng, AAD_BYTES)
            trace = 'AAD replaced with a distinct random value; expect tag_ok=0'

        ref_ct, ref_tag = ref_encrypt(key, iv, aad, pt)

        op0 = make_op_encrypt(key, iv, aad, pt, reset_before=True)
        op1 = _make_op_decrypt_prefilled(
            key, iv, bad_aad, pt, ref_ct, ref_tag,
            reset_before=True, check_tag_reject=True,
        )

        scenarios.append(TestScenario(
            category='tamper_aad',
            label=f'tamper_aad_{i:02d}',
            trace=trace,
            ops=[op0, op1],
        ))
    return scenarios

# ---------------------------------------------------------------------------
# Category 2 — tamper_tag (10 scenarios)
# ---------------------------------------------------------------------------

def _gen_tamper_tag(rng: random.Random) -> list[TestScenario]:
    """
    1 op each: decrypt with correct CT but a corrupted exp_tag_i.
    check_tag_reject=True, check_pt=False.
    """
    scenarios = []
    for i in range(10):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)

        ref_ct, ref_tag = ref_encrypt(key, iv, aad, pt)

        if i == 0:
            bad_tag = ref_tag ^ 0x1
            trace = 'expected tag bit 0 flipped; expect tag_ok=0'
        elif i == 1:
            bad_tag = ref_tag ^ (1 << (TAG_BYTES * 8 - 1))
            trace = f'expected tag bit {TAG_BYTES * 8 - 1} flipped; expect tag_ok=0'
        elif i == 2:
            bad_tag = (~ref_tag) & ((1 << (TAG_BYTES * 8)) - 1)
            trace = 'expected tag complemented; expect tag_ok=0'
        elif i == 3:
            bad_tag = 0
            trace = 'expected tag replaced with all zeros; expect tag_ok=0'
        elif i == 4:
            bad_tag = (1 << (TAG_BYTES * 8)) - 1
            trace = 'expected tag replaced with all ones; expect tag_ok=0'
        else:
            bad_tag = int.from_bytes(rand_bytes(rng, TAG_BYTES), 'big')
            while bad_tag == ref_tag:
                bad_tag = int.from_bytes(rand_bytes(rng, TAG_BYTES), 'big')
            trace = 'expected tag replaced with a distinct random value; expect tag_ok=0'

        op = _make_op_decrypt_prefilled(
            key, iv, aad, pt, ref_ct, bad_tag,
            reset_before=True, check_tag_reject=True,
        )

        scenarios.append(TestScenario(
            category='tamper_tag',
            label=f'tamper_tag_{i:02d}',
            trace=trace,
            ops=[op],
        ))
    return scenarios

# ---------------------------------------------------------------------------
# Category 3 — tamper_ct (10 scenarios)
# ---------------------------------------------------------------------------

def _gen_tamper_ct(rng: random.Random) -> list[TestScenario]:
    """Corrupt first, middle, and last ciphertext blocks and require rejection."""
    scenarios = []
    block_indices = [0, NBLOCKS // 2, NBLOCKS - 1, 0, NBLOCKS // 2,
                     NBLOCKS - 1, 0, NBLOCKS // 2, NBLOCKS - 1, NBLOCKS // 2]
    bit_indices = [0, 0, 0, 127, 127, 127, 63, 64, 31, 95]

    for i, (block_idx, bit_idx) in enumerate(zip(block_indices, bit_indices)):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        ref_ct, ref_tag = ref_encrypt(key, iv, aad, pt)

        bad_ct = list(ref_ct)
        bad_ct[block_idx] ^= 1 << bit_idx
        op = _make_op_decrypt_prefilled(
            key, iv, aad, pt, bad_ct, ref_tag,
            reset_before=True, check_tag_reject=True,
        )
        scenarios.append(TestScenario(
            category='tamper_ct',
            label=f'tamper_ct_{i:02d}',
            trace=f'CT[{block_idx:02d}] bit {bit_idx} flipped; expect tag_ok=0',
            ops=[op],
        ))
    return scenarios

# ---------------------------------------------------------------------------
# Category 4 — tamper_iv (5 scenarios)
# ---------------------------------------------------------------------------

def _gen_tamper_iv(rng: random.Random) -> list[TestScenario]:
    """Decrypt reference ciphertext with a modified IV and require rejection."""
    scenarios = []
    bit_indices = [0, IV_BYTES * 8 - 1, (IV_BYTES * 8) // 2, 23, 71]

    for i, bit_idx in enumerate(bit_indices):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        ref_ct, ref_tag = ref_encrypt(key, iv, aad, pt)

        bad_iv_int = int.from_bytes(iv, 'big') ^ (1 << bit_idx)
        bad_iv = bad_iv_int.to_bytes(IV_BYTES, 'big')
        op = _make_op_decrypt_prefilled(
            key, bad_iv, aad, pt, ref_ct, ref_tag,
            reset_before=True, check_tag_reject=True,
        )
        scenarios.append(TestScenario(
            category='tamper_iv',
            label=f'tamper_iv_{i:02d}',
            trace=f'IV bit {bit_idx} flipped; expect tag_ok=0',
            ops=[op],
        ))
    return scenarios

# ---------------------------------------------------------------------------
# Category 5 — tamper_key (5 scenarios)
# ---------------------------------------------------------------------------

def _gen_tamper_key(rng: random.Random) -> list[TestScenario]:
    """Decrypt reference ciphertext with a modified key and require rejection."""
    scenarios = []
    bit_indices = [0, KEY_BYTES * 8 - 1, (KEY_BYTES * 8) // 2, 31, 96]

    for i, bit_idx in enumerate(bit_indices):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        ref_ct, ref_tag = ref_encrypt(key, iv, aad, pt)

        bad_key_int = int.from_bytes(key, 'big') ^ (1 << bit_idx)
        bad_key = bad_key_int.to_bytes(KEY_BYTES, 'big')
        op = _make_op_decrypt_prefilled(
            bad_key, iv, aad, pt, ref_ct, ref_tag,
            reset_before=True, check_tag_reject=True,
        )
        scenarios.append(TestScenario(
            category='tamper_key',
            label=f'tamper_key_{i:02d}',
            trace=f'key bit {bit_idx} flipped; expect tag_ok=0',
            ops=[op],
        ))
    return scenarios

# ---------------------------------------------------------------------------
# Category 6 — mode_switching (8 scenarios)
# ---------------------------------------------------------------------------

def _gen_mode_switching(rng: random.Random) -> list[TestScenario]:
    """
    3 ops each, no resets between ops (only op0 resets).
    Patterns: enc→dec→enc (i<4), dec→enc→dec (i>=4).
    All CT/tag for decrypt ops come from the Python reference.
    """
    scenarios = []
    for i in range(8):
        if i < 4:
            # enc → dec → enc
            key_a = rand_bytes(rng, KEY_BYTES); iv_a = rand_bytes(rng, IV_BYTES)
            aad_a = rand_bytes(rng, AAD_BYTES); pt_a = rand_bytes(rng, PAYLOAD_BYTES)

            key_b = rand_bytes(rng, KEY_BYTES); iv_b = rand_bytes(rng, IV_BYTES)
            aad_b = rand_bytes(rng, AAD_BYTES); pt_b = rand_bytes(rng, PAYLOAD_BYTES)
            ref_ct_b, ref_tag_b = ref_encrypt(key_b, iv_b, aad_b, pt_b)

            key_c = rand_bytes(rng, KEY_BYTES); iv_c = rand_bytes(rng, IV_BYTES)
            aad_c = rand_bytes(rng, AAD_BYTES); pt_c = rand_bytes(rng, PAYLOAD_BYTES)

            op0 = make_op_encrypt(key_a, iv_a, aad_a, pt_a, reset_before=True)
            op1 = _make_op_decrypt_prefilled(
                key_b, iv_b, aad_b, pt_b, ref_ct_b, ref_tag_b,
                reset_before=False, check_pt=True, check_tag_ok=True,
            )
            op2 = make_op_encrypt(key_c, iv_c, aad_c, pt_c, reset_before=False)

        else:
            # dec → enc → dec
            key_a = rand_bytes(rng, KEY_BYTES); iv_a = rand_bytes(rng, IV_BYTES)
            aad_a = rand_bytes(rng, AAD_BYTES); pt_a = rand_bytes(rng, PAYLOAD_BYTES)
            ref_ct_a, ref_tag_a = ref_encrypt(key_a, iv_a, aad_a, pt_a)

            key_b = rand_bytes(rng, KEY_BYTES); iv_b = rand_bytes(rng, IV_BYTES)
            aad_b = rand_bytes(rng, AAD_BYTES); pt_b = rand_bytes(rng, PAYLOAD_BYTES)

            key_c = rand_bytes(rng, KEY_BYTES); iv_c = rand_bytes(rng, IV_BYTES)
            aad_c = rand_bytes(rng, AAD_BYTES); pt_c = rand_bytes(rng, PAYLOAD_BYTES)
            ref_ct_c, ref_tag_c = ref_encrypt(key_c, iv_c, aad_c, pt_c)

            op0 = _make_op_decrypt_prefilled(
                key_a, iv_a, aad_a, pt_a, ref_ct_a, ref_tag_a,
                reset_before=True, check_pt=True, check_tag_ok=True,
            )
            op1 = make_op_encrypt(key_b, iv_b, aad_b, pt_b, reset_before=False)
            op2 = _make_op_decrypt_prefilled(
                key_c, iv_c, aad_c, pt_c, ref_ct_c, ref_tag_c,
                reset_before=False, check_pt=True, check_tag_ok=True,
            )

        scenarios.append(TestScenario(
            category='mode_switching',
            label=f'mode_switch_{i:02d}',
            ops=[op0, op1, op2],
        ))
    return scenarios

# ---------------------------------------------------------------------------
# Category 4 — start_mid_op (8 scenarios)
# ---------------------------------------------------------------------------

def _gen_start_mid_op(rng: random.Random) -> list[TestScenario]:
    """
    1 op each: encrypt with special_action="start_mid_op".
    Runner drives 7 blocks, pulses start_i with junk params on the bus,
    then continues the remaining 7 blocks of the original operation.
    start_i is only sampled in ST_IDLE — mid-operation pulse must be ignored.
    check_ct=True against original params.
    """
    scenarios = []
    for i in range(8):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        op  = make_op_encrypt(key, iv, aad, pt, reset_before=True)
        op['special_action'] = 'start_mid_op'
        scenarios.append(TestScenario(
            category='start_mid_op',
            label=f'start_mid_op_{i:02d}',
            ops=[op],
        ))
    return scenarios

# ---------------------------------------------------------------------------
# Category 5 — double_start (5 scenarios)
# ---------------------------------------------------------------------------

def _gen_double_start(rng: random.Random) -> list[TestScenario]:
    """
    1 op each: encrypt with special_action="double_start".
    Runner holds start_i high for 2 cycles before deasserting.
    FSM should latch on the first rising edge that sees start_i=1 in ST_IDLE;
    the second cycle fires in ST_KEY_INIT and must be ignored.
    check_ct=True — operation must complete normally.
    """
    scenarios = []
    for i in range(5):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        op  = make_op_encrypt(key, iv, aad, pt, reset_before=True)
        op['special_action'] = 'double_start'
        scenarios.append(TestScenario(
            category='double_start',
            label=f'double_start_{i:02d}',
            ops=[op],
        ))
    return scenarios

# ---------------------------------------------------------------------------
# Category 6 — early_valid (8 scenarios)
# ---------------------------------------------------------------------------

def _gen_early_valid(rng: random.Random) -> list[TestScenario]:
    """
    1 op each: encrypt with special_action="early_valid".
    Runner asserts cipher_data_in_valid_i for 5 cycles while FSM is in IDLE,
    then deasserts and proceeds with a normal _start_operation + payload drive.
    FSM must ignore valid outside ST_PROC_PAYLOAD.  check_ct=True.
    """
    scenarios = []
    for i in range(8):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        op  = make_op_encrypt(key, iv, aad, pt, reset_before=True)
        op['special_action'] = 'early_valid'
        scenarios.append(TestScenario(
            category='early_valid',
            label=f'early_valid_{i:02d}',
            ops=[op],
        ))
    return scenarios

# ---------------------------------------------------------------------------
# Category 7 — watchdog (8 scenarios)
# ---------------------------------------------------------------------------

def _gen_watchdog(rng: random.Random) -> list[TestScenario]:
    """
    2 ops each.
    op0: watchdog_starve — start operation, drive no payload, wait
         WDT_STARVE_NS, assert rsp_error_o=1 and the cipher is idle again.
    op1: normal encrypt with reset_before=True — verifies FSM recovery.
    """
    scenarios = []
    for i in range(8):
        key_a = rand_bytes(rng, KEY_BYTES); iv_a = rand_bytes(rng, IV_BYTES)
        aad_a = rand_bytes(rng, AAD_BYTES); pt_a = rand_bytes(rng, PAYLOAD_BYTES)
        op0 = make_op_encrypt(key_a, iv_a, aad_a, pt_a, reset_before=True)
        op0['check_ct']       = False
        op0['special_action'] = 'watchdog_starve'

        key_b = rand_bytes(rng, KEY_BYTES); iv_b = rand_bytes(rng, IV_BYTES)
        aad_b = rand_bytes(rng, AAD_BYTES); pt_b = rand_bytes(rng, PAYLOAD_BYTES)
        op1 = make_op_encrypt(key_b, iv_b, aad_b, pt_b, reset_before=True)

        scenarios.append(TestScenario(
            category='watchdog',
            label=f'watchdog_{i:02d}',
            ops=[op0, op1],
        ))
    return scenarios

# ---------------------------------------------------------------------------
# Category 8 — reset_timing (8 scenarios)
# ---------------------------------------------------------------------------

_RESET_CYCLES = [1, 1, 2, 2, 4, 4, 8, 8]

def _gen_reset_timing(rng: random.Random) -> list[TestScenario]:
    """
    1 op each: normal encrypt, but the reset pulse is held for a non-default
    number of cycles (1, 1, 2, 2, 4, 4, 8, 8).  scenario.reset_cycles carries
    the value; the runner passes it to drv.reset().  check_ct=True.
    """
    scenarios = []
    for i, cycles in enumerate(_RESET_CYCLES):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        op  = make_op_encrypt(key, iv, aad, pt, reset_before=True)
        scenarios.append(TestScenario(
            category='reset_timing',
            label=f'reset_timing_{cycles}cyc_{i:02d}',
            ops=[op],
            reset_cycles=cycles,
        ))
    return scenarios

# ---------------------------------------------------------------------------
# Category 9 — same_key_burst (5 scenarios)
# ---------------------------------------------------------------------------

def _gen_same_key_burst(rng: random.Random) -> list[TestScenario]:
    """
    10 ops each: same key, random IV/AAD/PT per op.
    Only op0 resets (reset_before=True); ops 1-9 do not.
    All check_ct=True — verifies key expansion is stable across back-to-back
    operations sharing the same key without re-expansion.
    """
    scenarios = []
    for i in range(5):
        key = rand_bytes(rng, KEY_BYTES)
        ops = []
        for j in range(10):
            iv  = rand_bytes(rng, IV_BYTES)
            aad = rand_bytes(rng, AAD_BYTES)
            pt  = rand_bytes(rng, PAYLOAD_BYTES)
            ops.append(make_op_encrypt(key, iv, aad, pt, reset_before=(j == 0)))
        scenarios.append(TestScenario(
            category='same_key_burst',
            label=f'same_key_burst_{i:02d}',
            ops=ops,
        ))
    return scenarios

# ---------------------------------------------------------------------------
# Category 10 — zeros_exp_tag (10 scenarios)
# ---------------------------------------------------------------------------

def _gen_zeros_exp_tag(rng: random.Random) -> list[TestScenario]:
    """
    1 op each: decrypt with correct CT from the reference model but
    exp_tag_i=0x000...0.  check_tag_reject=True — the FSM must compare the
    computed GHASH tag against 0 and reject every time.
    """
    scenarios = []
    for i in range(10):
        key = rand_bytes(rng, KEY_BYTES)
        iv  = rand_bytes(rng, IV_BYTES)
        aad = rand_bytes(rng, AAD_BYTES)
        pt  = rand_bytes(rng, PAYLOAD_BYTES)
        ref_ct, _ = ref_encrypt(key, iv, aad, pt)
        op = _make_op_decrypt_prefilled(
            key, iv, aad, pt, ref_ct, 0,
            reset_before=True, check_tag_reject=True,
        )
        scenarios.append(TestScenario(
            category='zeros_exp_tag',
            label=f'zeros_exp_tag_{i:02d}',
            ops=[op],
        ))
    return scenarios

# ---------------------------------------------------------------------------
# Module-level failure-dict helpers (used by the runner)
# ---------------------------------------------------------------------------

def _make_fail(op_idx: int, op: dict, pt_blks: list,
               field: str, expected: int, got: int) -> dict:
    return {
        'op_idx': op_idx, 'op_mode': op['mode'],
        'key': op['key'], 'iv': op['iv'], 'aad': op['aad'],
        'pt_first_block': pt_blks[0], 'pt_last_block': pt_blks[-1],
        'field': field, 'expected': expected, 'got': got,
    }


def _check_enc_output(
    got_ct: list, got_tag: int,
    ref_ct: list, ref_tag: int,
    op: dict, op_idx: int, pt_blks: list,
) -> list[dict]:
    """Return a list of failure dicts (0 or more) for an encrypt op."""
    fails = []
    for blk_i in range(NBLOCKS):
        if got_ct[blk_i] != ref_ct[blk_i]:
            fails.append(_make_fail(op_idx, op, pt_blks,
                                    f'CT[{blk_i:02d}]', ref_ct[blk_i], got_ct[blk_i]))
            break
    if got_tag != ref_tag:
        fails.append(_make_fail(op_idx, op, pt_blks, 'TAG', ref_tag, got_tag))
    return fails

# ---------------------------------------------------------------------------
# Scenario list builder
# ---------------------------------------------------------------------------

def generate_negative_scenarios(rng: random.Random) -> list[TestScenario]:
    scenarios: list[TestScenario] = []
    scenarios.extend(_gen_tamper_aad(rng))        # 10
    scenarios.extend(_gen_tamper_tag(rng))        # 10
    scenarios.extend(_gen_tamper_ct(rng))         # 10
    scenarios.extend(_gen_tamper_iv(rng))         #  5
    scenarios.extend(_gen_tamper_key(rng))        #  5
    scenarios.extend(_gen_mode_switching(rng))    #  8
    scenarios.extend(_gen_start_mid_op(rng))      #  8
    scenarios.extend(_gen_double_start(rng))      #  5
    scenarios.extend(_gen_early_valid(rng))       #  8
    scenarios.extend(_gen_watchdog(rng))          #  8
    scenarios.extend(_gen_reset_timing(rng))      #  8
    scenarios.extend(_gen_same_key_burst(rng))    #  5
    scenarios.extend(_gen_zeros_exp_tag(rng))     # 10
    assert len(scenarios) == 100, f'Expected 100 scenarios, got {len(scenarios)}'
    return scenarios

# ---------------------------------------------------------------------------
# Module-level scenario list
# ---------------------------------------------------------------------------

SCENARIOS = generate_negative_scenarios(random.Random(7777))

# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

@cocotb.test(timeout_time=max(10 * 60 * 1_000_000_000,
                              300 * (op_cycles() + WDT_TIMEOUT) * CLK_NS),
             timeout_unit='ns')
async def test_negative_suite(dut):
    """Execute all negative and robustness scenarios."""
    cocotb.start_soon(Clock(dut.clk_i, CLK_NS, unit='ns').start())
    dut._log.info(f'Geometry: {GEOMETRY_DESC}')
    check_dut_geometry(dut)
    drv = AesGcmDriver(dut)
    total_scenarios = len(SCENARIOS)

    results: dict[str, list] = {}
    for s in SCENARIOS:
        if s.category not in results:
            results[s.category] = []

    cat_ops_count: dict[str, int] = {}
    for s in SCENARIOS:
        if s.category not in cat_ops_count:
            cat_ops_count[s.category] = len(s.ops)

    for s_idx, scenario in enumerate(SCENARIOS):
        trace = f' — {scenario.trace}' if scenario.trace else ''
        dut._log.info(
            f'RUN  [{s_idx + 1:03d}/{total_scenarios:03d}] '
            f'{scenario.label} ({scenario.category}){trace}'
        )

        scenario_failure_details: list[dict] = []

        for op_idx, op in enumerate(scenario.ops):
            key_i   = int.from_bytes(op['key'], 'big')
            iv_i    = int.from_bytes(op['iv'],  'big')
            aad_i   = int.from_bytes(op['aad'], 'big')
            pt_blks = pt_to_blocks(op['pt'])
            special = op.get('special_action')

            # ----------------------------------------------------------------
            # watchdog_starve — start op, starve payload, check err_o
            # ----------------------------------------------------------------
            if special == 'watchdog_starve':
                if op['reset_before']:
                    await drv.reset(scenario.reset_cycles)
                await drv._start_operation(mode=1, key=key_i, iv=iv_i, aad=aad_i)
                while int(dut.data_in_ready_o.value) == 0:
                    await RisingEdge(dut.clk_i)
                    await Timer(1, unit='ns')
                await Timer(WDT_STARVE_NS, unit='ns')
                dut.rsp_ready_i.value = 1
                await RisingEdge(dut.clk_i)
                await Timer(1, unit='ns')
                err_val  = int(dut.rsp_error_o.value)
                busy_val = 1 - int(dut.cmd_ready_o.value)
                if err_val != 1:
                    scenario_failure_details.append(
                        _make_fail(op_idx, op, pt_blks, 'err_o', 1, err_val))
                if busy_val != 0:
                    scenario_failure_details.append(
                        _make_fail(op_idx, op, pt_blks, 'busy_o', 0, busy_val))

            # ----------------------------------------------------------------
            # start_mid_op — drive MID_OP_BLOCKS, inject start_i, finish the rest
            # ----------------------------------------------------------------
            elif special == 'start_mid_op':
                await drv.reset(scenario.reset_cycles)
                await drv._start_operation(mode=1, key=key_i, iv=iv_i, aad=aad_i)
                cap_task = cocotb.start_soon(
                    drv._capture_output_stream(mode=1, aad=aad_i)
                )
                # First half via driver (deasserts valid after each block)
                await drv._drive_payload(pt_blks[:MID_OP_BLOCKS])
                # One-cycle garbage start_i pulse in ST_PROC_PAYLOAD
                await RisingEdge(dut.clk_i)
                await Timer(1, unit='ns')
                dut.cmd_valid_i.value = 1
                dut.cmd_key_i.value   = 0
                await RisingEdge(dut.clk_i)
                await Timer(1, unit='ns')
                dut.cmd_valid_i.value = 0
                dut.cmd_key_i.value   = key_i
                # Drive the remaining blocks manually (mirror _drive_payload streaming pattern)
                remaining = pt_blks[MID_OP_BLOCKS:]
                for bi, blk in enumerate(remaining):
                    while dut.data_in_ready_o.value == 0:
                        await RisingEdge(dut.clk_i)
                        await Timer(1, unit='ns')
                    dut.data_in_i.value       = blk
                    dut.data_in_valid_i.value = 1
                    await RisingEdge(dut.clk_i)
                    await Timer(1, unit='ns')
                    dut.data_in_valid_i.value = 0
                    nxt = remaining[bi + 1] if bi + 1 < len(remaining) else 0
                    dut.data_in_i.value = nxt
                output_words = await cap_task
                got_ct = output_words[:NBLOCKS]
                got_tag = output_words[NBLOCKS]
                await drv._wait_done()
                drv.validate_encrypt_stream(output_words, aad=aad_i)
                if op['check_ct']:
                    ref_ct, ref_tag = ref_encrypt(op['key'], op['iv'], op['aad'], op['pt'])
                    scenario_failure_details.extend(
                        _check_enc_output(got_ct, got_tag, ref_ct, ref_tag,
                                          op, op_idx, pt_blks))

            # ----------------------------------------------------------------
            # double_start — hold start_i for 2 cycles, op must complete normally
            # ----------------------------------------------------------------
            elif special == 'double_start':
                await drv.reset(scenario.reset_cycles)
                await RisingEdge(dut.clk_i)
                await Timer(1, unit='ns')
                dut.cmd_valid_i.value   = 1
                dut.cmd_mode_i.value    = 1
                dut.cmd_key_i.value     = key_i
                dut.cmd_iv_i.value      = iv_i
                dut.cmd_aad_i.value     = aad_i
                dut.cmd_exp_tag_i.value = 0
                # Second cycle: start_i still asserted (FSM now in ST_KEY_INIT)
                await RisingEdge(dut.clk_i)
                await Timer(1, unit='ns')
                dut.cmd_valid_i.value = 0
                dut.rsp_ready_i.value = 0
                # Wait for ST_PROC_PAYLOAD
                while dut.data_in_ready_o.value == 0:
                    await RisingEdge(dut.clk_i)
                    await Timer(1, unit='ns')
                cap_task = cocotb.start_soon(
                    drv._capture_output_stream(mode=1, aad=aad_i)
                )
                drive_task = cocotb.start_soon(drv._drive_payload(pt_blks))
                await drive_task
                output_words = await cap_task
                got_ct = output_words[:NBLOCKS]
                got_tag = output_words[NBLOCKS]
                await drv._wait_done()
                drv.validate_encrypt_stream(output_words, aad=aad_i)
                if op['check_ct']:
                    ref_ct, ref_tag = ref_encrypt(op['key'], op['iv'], op['aad'], op['pt'])
                    scenario_failure_details.extend(
                        _check_enc_output(got_ct, got_tag, ref_ct, ref_tag,
                                          op, op_idx, pt_blks))

            # ----------------------------------------------------------------
            # early_valid — assert valid before start, op must complete normally
            # ----------------------------------------------------------------
            elif special == 'early_valid':
                await drv.reset(scenario.reset_cycles)
                # Assert valid with zero data for 5 cycles while FSM is in IDLE
                dut.data_in_valid_i.value = 1
                dut.data_in_i.value       = 0
                for _ in range(5):
                    await RisingEdge(dut.clk_i)
                await Timer(1, unit='ns')
                dut.data_in_valid_i.value = 0
                # Normal operation (no second reset — FSM must have ignored early valid)
                await drv._start_operation(mode=1, key=key_i, iv=iv_i, aad=aad_i)
                cap_task = cocotb.start_soon(
                    drv._capture_output_stream(mode=1, aad=aad_i)
                )
                drive_task = cocotb.start_soon(drv._drive_payload(pt_blks))
                await drive_task
                output_words = await cap_task
                got_ct = output_words[:NBLOCKS]
                got_tag = output_words[NBLOCKS]
                await drv._wait_done()
                drv.validate_encrypt_stream(output_words, aad=aad_i)
                if op['check_ct']:
                    ref_ct, ref_tag = ref_encrypt(op['key'], op['iv'], op['aad'], op['pt'])
                    scenario_failure_details.extend(
                        _check_enc_output(got_ct, got_tag, ref_ct, ref_tag,
                                          op, op_idx, pt_blks))

            # ----------------------------------------------------------------
            # Normal encrypt
            # ----------------------------------------------------------------
            elif op['mode'] == 'encrypt':
                if op['reset_before']:
                    await drv.reset(scenario.reset_cycles)
                got_ct, got_tag = await drv.run_encrypt(key_i, iv_i, aad_i, pt_blks)
                if op['check_ct']:
                    ref_ct, ref_tag = ref_encrypt(op['key'], op['iv'], op['aad'], op['pt'])
                    scenario_failure_details.extend(
                        _check_enc_output(got_ct, got_tag, ref_ct, ref_tag,
                                          op, op_idx, pt_blks))

            # ----------------------------------------------------------------
            # Normal decrypt
            # ----------------------------------------------------------------
            else:
                if op['reset_before']:
                    await drv.reset(scenario.reset_cycles)
                if op['ct_blocks'] is not None:
                    ct_feed  = op['ct_blocks']
                    tag_feed = op['exp_tag']
                elif op.get('use_ref_ct'):
                    ct_feed, tag_feed = ref_encrypt(op['key'], op['iv'],
                                                    op['aad'], op['pt'])
                else:
                    raise ValueError(
                        f'No CT source for decrypt op [{op_idx}] in {scenario.label}')
                got_pt, tag_ok = await drv.run_decrypt(
                    key_i, iv_i, aad_i, ct_feed, tag_feed)
                if op['check_pt']:
                    for blk_i in range(NBLOCKS):
                        if got_pt[blk_i] != pt_blks[blk_i]:
                            scenario_failure_details.append(_make_fail(
                                op_idx, op, pt_blks,
                                f'PT[{blk_i:02d}]', pt_blks[blk_i], got_pt[blk_i]))
                            break
                if op['check_tag_ok'] and tag_ok != 1:
                    scenario_failure_details.append(
                        _make_fail(op_idx, op, pt_blks, 'tag_ok', 1, tag_ok))
                if op['check_tag_reject'] and tag_ok != 0:
                    scenario_failure_details.append(
                        _make_fail(op_idx, op, pt_blks, 'tag_ok', 0, tag_ok))

        passed = not scenario_failure_details
        results[scenario.category].append(
            (scenario.label, passed, scenario_failure_details))
        outcome = 'PASS' if passed else 'FAIL'
        dut._log.info(
            f'{outcome} [{s_idx + 1:03d}/{total_scenarios:03d}] '
            f'{scenario.label}'
        )

    # ------------------------------------------------------------------
    # Terminal summary
    # ------------------------------------------------------------------
    total_passed      = 0
    total_ops         = sum(len(s.ops) for s in SCENARIOS)
    all_failed_labels: list[str] = []

    for category, entries in results.items():
        cat_pass  = sum(1 for _, p, _ in entries if p)
        cat_total = len(entries)
        total_passed += cat_pass
        dut._log.info(f'{category}: {cat_pass}/{cat_total}')
        for label, passed, _ in entries:
            if not passed:
                all_failed_labels.append(label)

    total_failed = total_scenarios - total_passed
    dut._log.info(
        f'TOTAL: {total_passed}/{total_scenarios} — '
        f'{total_failed} failure(s)'
    )

    # ------------------------------------------------------------------
    # Report file
    # ------------------------------------------------------------------
    try:
        from cocotb.utils import get_sim_time as _get_sim_time
        sim_time_str = f'{_get_sim_time("ns"):.0f} ns'
    except Exception:
        sim_time_str = 'N/A'

    report_path = (
        Path(__file__).resolve().parents[2]
        / 'build' / 'reports'
        / f'report_negative_suite_k{KEY_BYTES * 8}_p{PAYLOAD_BYTES + 32}.txt'
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    SEP_HEAVY   = '═' * 56
    SEP_LIGHT   = '─' * 56

    with report_path.open('w') as rpt:
        def w(line=''):
            rpt.write(line + '\n')

        w(SEP_HEAVY)
        w(f'AES-{KEY_BYTES * 8}-GCM Negative / Robustness Test Report')
        w(SEP_HEAVY)
        w(f'Date:       {datetime.now().isoformat()}')
        w(f'Seed:       7777')
        w(f'Simulator:  {SIM_NAME} (cocotb)')
        w(f'Geometry:   {GEOMETRY_DESC}')
        w(SEP_LIGHT)
        w(f'Scenarios:  {total_scenarios}')
        w(f'Operations: {total_ops}')
        w(f'Passed:     {total_passed}/{total_scenarios}')
        w(f'Failed:     {total_failed}/{total_scenarios}')
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
            w(f'VERDICT: ALL {total_scenarios} SCENARIOS PASSED')
        else:
            w(f'VERDICT: {total_failed} FAILURE(S)')
        w(SEP_HEAVY)

    dut._log.info(f'Report written to {report_path}')

    assert total_passed == total_scenarios, (
        f'Negative suite: {total_failed} failure(s) — see report_negative_suite.txt'
    )
