# AES-GCM geometry, key-size and watchdog checks for the parameterised block.
# Author: Baris
# Date: 2026-09-18
#
# These tests exist for the features added by aes_gcm_ip on top of the
# original AES-128 / 256-byte block and are meant to be run for every entry
# of the configuration matrix (see Makefile `matrix`):
#
#   test_block_counts        exact input/output beat counts and `last` position
#   test_page_layout         byte offsets of CT | TAG | AAD inside one page
#   test_key_size_binding    the RTL really runs AES-KEY_W (and not the other size)
#   test_key_zeroised        the FSM key register is cleared after expansion
#   test_watchdog_threshold  input starvation aborts at WDT_TIMEOUT (+ small skew)
#   test_watchdog_margin     a stall just below the threshold completes normally
#   test_decrypt_response_after_last  decrypt response waits for tag finalisation

import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import FallingEdge, RisingEdge, Timer
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aes_gcm_driver import (
    AAD_BYTES,
    BLOCK_BYTES,
    ENC_TOTAL_BLOCKS,
    GEOMETRY_DESC,
    IV_BYTES,
    KEY_BYTES,
    KEY_W,
    NBLOCKS,
    PAGE_BYTES,
    PAYLOAD_BYTES,
    TAG_BYTES,
    WDT_TIMEOUT,
    AesGcmDriver,
    bytes_to_blocks,
    check_dut_geometry,
    op_cycles,
    pattern_bytes,
)

CLK_NS = 10
OP_TIMEOUT_NS = 6 * (op_cycles() + WDT_TIMEOUT) * CLK_NS

KEY = (bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c') if KEY_BYTES == 16 else
       bytes.fromhex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'))
IV = bytes.fromhex('cafebabefacedbaddecaf888')
AAD = bytes.fromhex('feedfacedeadbeeffeedfacedeadbeef')
PT = pattern_bytes(PAYLOAD_BYTES)


def ref_encrypt(key: bytes, iv: bytes, aad: bytes, pt: bytes):
    raw = AESGCM(key).encrypt(iv, pt, aad)
    return bytes_to_blocks(raw[:-TAG_BYTES]), int.from_bytes(raw[-TAG_BYTES:], 'big')


async def _setup(dut):
    cocotb.start_soon(Clock(dut.clk_i, CLK_NS, unit='ns').start())
    dut._log.info(f'Geometry: {GEOMETRY_DESC}')
    check_dut_geometry(dut)
    drv = AesGcmDriver(dut)
    await drv.reset()
    return drv


def _settle():
    return Timer(1, unit='ns')


class _Counters:
    """Count accepted input beats, output beats and `last` beats."""

    def __init__(self, dut):
        self.dut = dut
        self.inputs = 0
        self.outputs = 0
        self.lasts = 0
        self.last_index = None
        self.ready_after_done = 0
        self.stop = False

    async def run(self):
        dut = self.dut
        while not self.stop:
            await RisingEdge(dut.clk_i)
            # sample the values that were present at the edge
            done_before = self.inputs >= NBLOCKS
            if int(dut.data_in_valid_i.value) and int(dut.data_in_ready_o.value):
                self.inputs += 1
            if int(dut.data_out_valid_o.value) and int(dut.data_out_ready_i.value):
                if int(dut.data_out_last_o.value):
                    self.lasts += 1
                    self.last_index = self.outputs
                self.outputs += 1
            if done_before and int(dut.data_in_ready_o.value):
                self.ready_after_done += 1
            await _settle()


# ---------------------------------------------------------------------------
# 1. Exact beat counts
# ---------------------------------------------------------------------------
@cocotb.test(timeout_time=OP_TIMEOUT_NS, timeout_unit='ns')
async def test_block_counts(dut):
    """Encrypt: NBLOCKS in, NBLOCKS+2 out, last on the final beat. Decrypt: NBLOCKS out."""
    drv = await _setup(dut)
    exp_ct, exp_tag = ref_encrypt(KEY, IV, AAD, PT)

    cnt = _Counters(dut)
    task = cocotb.start_soon(cnt.run())
    got_ct, got_tag = await drv.run_encrypt(
        int.from_bytes(KEY, 'big'), int.from_bytes(IV, 'big'),
        int.from_bytes(AAD, 'big'), bytes_to_blocks(PT),
        ready_pattern=[1, 0, 1, 1, 0], payload_gaps=[0, 2, 1])
    cnt.stop = True
    await task
    assert got_ct == exp_ct and got_tag == exp_tag, 'encrypt output mismatch vs reference'
    assert cnt.inputs == NBLOCKS, f'encrypt accepted {cnt.inputs} input beats, expected {NBLOCKS}'
    assert cnt.outputs == ENC_TOTAL_BLOCKS, f'encrypt produced {cnt.outputs} beats, expected {ENC_TOTAL_BLOCKS}'
    assert cnt.lasts == 1 and cnt.last_index == ENC_TOTAL_BLOCKS - 1, \
        f'encrypt last asserted {cnt.lasts}x at index {cnt.last_index}'
    assert cnt.ready_after_done == 0, 'data_in_ready_o asserted after the final payload block'

    await drv.reset()
    cnt = _Counters(dut)
    task = cocotb.start_soon(cnt.run())
    got_pt, tag_ok = await drv.run_decrypt(
        int.from_bytes(KEY, 'big'), int.from_bytes(IV, 'big'),
        int.from_bytes(AAD, 'big'), exp_ct, exp_tag,
        ready_pattern=[0, 1], payload_gaps=[1])
    cnt.stop = True
    await task
    assert got_pt == bytes_to_blocks(PT) and tag_ok == 1, 'decrypt output mismatch'
    assert cnt.inputs == NBLOCKS, f'decrypt accepted {cnt.inputs} input beats, expected {NBLOCKS}'
    assert cnt.outputs == NBLOCKS, f'decrypt produced {cnt.outputs} beats, expected {NBLOCKS}'
    assert cnt.lasts == 1 and cnt.last_index == NBLOCKS - 1, \
        f'decrypt last asserted {cnt.lasts}x at index {cnt.last_index}'
    assert cnt.ready_after_done == 0, 'data_in_ready_o asserted after the final payload block'


# ---------------------------------------------------------------------------
# 2. Page layout
# ---------------------------------------------------------------------------
@cocotb.test(timeout_time=OP_TIMEOUT_NS, timeout_unit='ns')
async def test_page_layout(dut):
    """The concatenated encrypt output is exactly one page: CT | TAG | AAD."""
    drv = await _setup(dut)
    raw = AESGCM(KEY).encrypt(IV, PT, AAD)
    exp_ct_bytes, exp_tag_bytes = raw[:-TAG_BYTES], raw[-TAG_BYTES:]

    words = []

    async def capture():
        while len(words) < ENC_TOTAL_BLOCKS:
            await RisingEdge(dut.clk_i)
            if int(dut.data_out_valid_o.value) and int(dut.data_out_ready_i.value):
                words.append(int(dut.data_out_o.value))
            await _settle()

    cap = cocotb.start_soon(capture())
    await drv.run_encrypt(
        int.from_bytes(KEY, 'big'), int.from_bytes(IV, 'big'),
        int.from_bytes(AAD, 'big'), bytes_to_blocks(PT))
    await cap

    page = b''.join(w.to_bytes(BLOCK_BYTES, 'big') for w in words)
    assert len(page) == PAGE_BYTES, f'page is {len(page)} B, expected {PAGE_BYTES}'
    assert page[:PAYLOAD_BYTES] == exp_ct_bytes, 'ciphertext region mismatch'
    assert page[PAYLOAD_BYTES:PAYLOAD_BYTES + TAG_BYTES] == exp_tag_bytes, \
        f'tag not at byte offset {PAYLOAD_BYTES}'
    assert page[PAYLOAD_BYTES + TAG_BYTES:] == AAD, \
        f'AAD not at byte offset {PAYLOAD_BYTES + TAG_BYTES}'
    dut._log.info(f'page layout OK: CT[0:{PAYLOAD_BYTES}] TAG[{PAYLOAD_BYTES}:{PAYLOAD_BYTES + 16}] '
                  f'AAD[{PAYLOAD_BYTES + 16}:{PAGE_BYTES}]')


# ---------------------------------------------------------------------------
# 3. Key-size binding
# ---------------------------------------------------------------------------
@cocotb.test(timeout_time=OP_TIMEOUT_NS, timeout_unit='ns')
async def test_key_size_binding(dut):
    """Output matches AES-KEY_W and differs from the other key size on the same bits."""
    drv = await _setup(dut)
    rng = random.Random(0xC0FFEE ^ KEY_W)
    key = rng.randbytes(KEY_BYTES)
    iv = rng.randbytes(IV_BYTES)
    aad = rng.randbytes(AAD_BYTES)
    pt = rng.randbytes(PAYLOAD_BYTES)

    got_ct, got_tag = await drv.run_encrypt(
        int.from_bytes(key, 'big'), int.from_bytes(iv, 'big'),
        int.from_bytes(aad, 'big'), bytes_to_blocks(pt))

    exp_ct, exp_tag = ref_encrypt(key, iv, aad, pt)
    assert got_ct == exp_ct and got_tag == exp_tag, f'output does not match AES-{KEY_W} reference'

    # The wrong key length on the same key material must NOT match. For a
    # 128-bit configuration compare against AES-256 with the key in the upper
    # half (how the Secworks core is fed); for 256 compare against AES-128 on
    # the upper half.
    other_key = key + bytes(16) if KEY_BYTES == 16 else key[:16]
    oth_ct, oth_tag = ref_encrypt(other_key, iv, aad, pt)
    assert got_tag != oth_tag and got_ct[0] != oth_ct[0], \
        'output also matches the other key size: keylen wiring is wrong'


# ---------------------------------------------------------------------------
# 4. Key zeroisation
# ---------------------------------------------------------------------------
@cocotb.test(timeout_time=OP_TIMEOUT_NS, timeout_unit='ns')
async def test_key_zeroised(dut):
    """The FSM key register is zero once the first payload block is requested."""
    drv = await _setup(dut)
    try:
        key_reg = dut.u_aes_fsm.reg_key_q
    except AttributeError:
        dut._log.warning('reg_key_q not visible in this simulator build, skipping')
        return
    key = pattern_bytes(KEY_BYTES, 0xA1)
    await drv._start_operation(mode=1, key=int.from_bytes(key, 'big'),
                               iv=int.from_bytes(IV, 'big'), aad=int.from_bytes(AAD, 'big'))
    # key must be present right after accept
    await _settle()
    assert int(key_reg.value) == int.from_bytes(key, 'big'), 'key not latched at accept'
    while int(dut.data_in_ready_o.value) == 0:
        await RisingEdge(dut.clk_i)
        await _settle()
    assert int(key_reg.value) == 0, 'FSM key register not zeroised after key expansion'
    # finish the operation cleanly
    cap = cocotb.start_soon(drv._capture_output_stream(mode=1, aad=int.from_bytes(AAD, 'big')))
    await drv._drive_payload(bytes_to_blocks(PT))
    await cap
    await drv._wait_done(mode=1)


# ---------------------------------------------------------------------------
# 5. Watchdog threshold
# ---------------------------------------------------------------------------
async def _cycles_until_error(dut, drv) -> int:
    """Start an encrypt, never provide payload, count cycles to rsp_valid && error."""
    await drv._start_operation(mode=1, key=int.from_bytes(KEY, 'big'),
                               iv=int.from_bytes(IV, 'big'), aad=int.from_bytes(AAD, 'big'))
    cycles = 0
    while True:
        await RisingEdge(dut.clk_i)
        await _settle()
        cycles += 1
        if int(dut.rsp_valid_o.value):
            assert int(dut.rsp_error_o.value) == 1, 'response without error flag during starvation'
            break
        assert cycles < WDT_TIMEOUT + 64, 'watchdog did not fire'
    dut.rsp_ready_i.value = 1
    await RisingEdge(dut.clk_i)
    await _settle()
    dut.rsp_ready_i.value = 0
    await RisingEdge(dut.clk_i)
    await _settle()
    assert int(dut.rsp_valid_o.value) == 0, 'error response not cleared by acknowledge'
    assert int(dut.cmd_ready_o.value) == 1, 'cmd_ready_o not restored after error acknowledge'
    return cycles


@cocotb.test(timeout_time=OP_TIMEOUT_NS, timeout_unit='ns')
async def test_watchdog_threshold(dut):
    """Starved input aborts WDT_TIMEOUT (+ a few cycles of skew) after command accept."""
    drv = await _setup(dut)
    cycles = await _cycles_until_error(dut, drv)
    dut._log.info(f'watchdog fired {cycles} cycles after command accept (WDT_TIMEOUT={WDT_TIMEOUT})')
    assert WDT_TIMEOUT <= cycles <= WDT_TIMEOUT + 8, \
        f'watchdog fired after {cycles} cycles, expected {WDT_TIMEOUT}..{WDT_TIMEOUT + 8}'
    # the block is usable again without a reset
    exp_ct, exp_tag = ref_encrypt(KEY, IV, AAD, PT)
    got_ct, got_tag = await drv.run_encrypt(
        int.from_bytes(KEY, 'big'), int.from_bytes(IV, 'big'),
        int.from_bytes(AAD, 'big'), bytes_to_blocks(PT))
    assert (got_ct, got_tag) == (exp_ct, exp_tag), 'operation after watchdog recovery failed'


@cocotb.test(timeout_time=OP_TIMEOUT_NS, timeout_unit='ns')
async def test_watchdog_margin(dut):
    """An input gap of WDT_TIMEOUT - 600 cycles between blocks completes normally."""
    drv = await _setup(dut)
    if WDT_TIMEOUT < 700:
        dut._log.warning('WDT_TIMEOUT too small for the margin test, skipping')
        return
    gap = WDT_TIMEOUT - 600   # setup phase consumes ~257 cycles before the first block
    exp_ct, exp_tag = ref_encrypt(KEY, IV, AAD, PT)
    gaps = [gap] + [0] * max(0, NBLOCKS - 1)
    got_ct, got_tag = await drv.run_encrypt(
        int.from_bytes(KEY, 'big'), int.from_bytes(IV, 'big'),
        int.from_bytes(AAD, 'big'), bytes_to_blocks(PT), payload_gaps=gaps)
    assert (got_ct, got_tag) == (exp_ct, exp_tag), 'operation with a long legal input gap failed'


# ---------------------------------------------------------------------------
# 6. Decrypt response timing
# ---------------------------------------------------------------------------
@cocotb.test(timeout_time=OP_TIMEOUT_NS, timeout_unit='ns')
async def test_decrypt_response_after_last(dut):
    """On decrypt, rsp_valid_o comes strictly after the final plaintext beat (tag finalisation)."""
    drv = await _setup(dut)
    exp_ct, exp_tag = ref_encrypt(KEY, IV, AAD, PT)
    last_cycle = None
    rsp_cycle = None
    cycle = 0
    stop = False

    async def monitor():
        nonlocal last_cycle, rsp_cycle, cycle
        while not stop:
            await RisingEdge(dut.clk_i)
            cycle += 1
            if int(dut.data_out_valid_o.value) and int(dut.data_out_ready_i.value) \
                    and int(dut.data_out_last_o.value) and last_cycle is None:
                last_cycle = cycle
            if int(dut.rsp_valid_o.value) and rsp_cycle is None:
                rsp_cycle = cycle
            await _settle()

    mon = cocotb.start_soon(monitor())
    got_pt, tag_ok = await drv.run_decrypt(
        int.from_bytes(KEY, 'big'), int.from_bytes(IV, 'big'),
        int.from_bytes(AAD, 'big'), exp_ct, exp_tag)
    stop = True
    await mon
    assert got_pt == bytes_to_blocks(PT) and tag_ok == 1
    assert last_cycle is not None and rsp_cycle is not None
    dut._log.info(f'decrypt: last PT beat at cycle {last_cycle}, response at cycle {rsp_cycle} '
                  f'(+{rsp_cycle - last_cycle})')
    # tag finalisation is one GHASH multiply (128 cycles) plus a few cycles
    assert rsp_cycle - last_cycle >= 128, 'decrypt response arrived before tag finalisation'
