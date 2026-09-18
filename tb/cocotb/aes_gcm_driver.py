# Reusable cocotb driver for aes_gcm_top (parameterised aes_gcm_ip build).
# Author: Baris
# Date: 2026-06-01, geometry-from-environment: 2026-09-18
#
# The DUT geometry is not hard-coded here. tb/cocotb/Makefile passes the same
# KEY_W / PAGE_BYTES / WDT_TIMEOUT it gives the simulator as environment
# variables, and every constant below is derived from them, so all suites
# scale with the configuration under test.

import os

import cocotb
from cocotb.triggers import FallingEdge, RisingEdge, Timer


class _StopEvent:
    """Minimal stop flag for _protocol_monitor."""
    def __init__(self): self._set = False
    def set(self):       self._set = True
    def is_set(self):    return self._set

# ---------------------------------------------------------------------------
# Geometry (mirrors the aes_gcm_top parameters and derived localparams)
# ---------------------------------------------------------------------------
KEY_W       = int(os.getenv('AES_KEY_W', '128'))
PAGE_BYTES  = int(os.getenv('AES_PAGE_BYTES', '256'))
WDT_TIMEOUT = int(os.getenv('AES_WDT_TIMEOUT', '4095'))
SIM_NAME    = os.getenv('SIM', 'unknown')

assert KEY_W in (128, 256), f'AES_KEY_W must be 128 or 256, got {KEY_W}'

BLOCK_BYTES = 16
KEY_BYTES = KEY_W // 8
IV_BYTES = 12
AAD_BYTES = 16
TAG_BYTES = 16
META_BYTES = TAG_BYTES + AAD_BYTES
PAYLOAD_BYTES = PAGE_BYTES - META_BYTES

assert PAGE_BYTES % BLOCK_BYTES == 0, f'AES_PAGE_BYTES must be a multiple of 16, got {PAGE_BYTES}'
assert PAYLOAD_BYTES >= BLOCK_BYTES, f'AES_PAGE_BYTES must be >= 48, got {PAGE_BYTES}'

NBLOCKS = PAYLOAD_BYTES // BLOCK_BYTES
BLOCK_HEX_DIGITS = BLOCK_BYTES * 2
ENC_TOTAL_BLOCKS = NBLOCKS + 2
DEC_TOTAL_BLOCKS = NBLOCKS

GEOMETRY_DESC = (
    f'AES-{KEY_W}, {IV_BYTES * 8}-bit IV, '
    f'{AAD_BYTES * 8}-bit AAD, {PAGE_BYTES} B page = {PAYLOAD_BYTES} B payload '
    f'({NBLOCKS} blocks) + {TAG_BYTES}-B tag + {AAD_BYTES}-B AAD, '
    f'WDT_TIMEOUT={WDT_TIMEOUT}'
)

# Cycle budget for one operation, used to size cocotb timeouts. Measured
# values (always-ready sink): 256/300 cycles setup (AES-128/256), 183/203 per block, ~261
# cycles finalisation. Generous margins on top.
SETUP_CYCLES = 400
BLOCK_CYCLES = 220
FINAL_CYCLES = 400


def op_cycles(nblocks: int = NBLOCKS) -> int:
    """Upper-bound cycle estimate for one encrypt or decrypt operation."""
    return SETUP_CYCLES + nblocks * BLOCK_CYCLES + FINAL_CYCLES


def pattern_bytes(n: int, offset: int = 0) -> bytes:
    """n bytes of (offset + i) & 0xFF: a counting pattern valid for any n."""
    return bytes((offset + i) & 0xFF for i in range(n))


def check_dut_geometry(dut) -> None:
    """Cross-check the simulator's parameters against the environment.

    Parameter handles are not exposed by every simulator; missing handles are
    reported and skipped rather than failing the run.
    """
    for name, expected in (('KEY_W', KEY_W), ('PAGE_BYTES', PAGE_BYTES),
                           ('WDT_TIMEOUT', WDT_TIMEOUT), ('NBLOCKS', NBLOCKS)):
        try:
            got = int(getattr(dut, name).value)
        except Exception:
            dut._log.info(f'geometry: parameter {name} not visible to cocotb, skipping check')
            continue
        assert got == expected, f'DUT {name}={got} but environment expects {expected}'

PLAINTEXT_POISON = int('a5' * BLOCK_BYTES, 16)
SPI_POISON = int('5a' * BLOCK_BYTES, 16)


def bytes_to_blocks(data: bytes) -> list[int]:
    """Split a payload into fixed-width big-endian blocks."""
    assert len(data) == PAYLOAD_BYTES
    return [
        int.from_bytes(data[offset:offset + BLOCK_BYTES], 'big')
        for offset in range(0, PAYLOAD_BYTES, BLOCK_BYTES)
    ]


class AesGcmDriver:
    """
    Drive aes_gcm_top through encrypt and decrypt operations.

    Convention: all key/iv/aad/block values are plain Python integers
    (128-bit big-endian).  The caller converts bytes → int with
    int.from_bytes(b, 'big') before passing them in.
    """

    def __init__(self, dut):
        self.dut = dut

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def reset(self, cycles: int = 4) -> None:
        """Assert rst_ni=0 for `cycles` clocks, then release."""
        dut = self.dut
        dut.rst_ni.value                  = 0
        dut.cmd_valid_i.value          = 0
        dut.cmd_mode_i.value           = 1   # default: encrypt
        dut.cmd_key_i.value            = 0
        dut.cmd_iv_i.value             = 0
        dut.cmd_aad_i.value            = 0
        dut.cmd_exp_tag_i.value        = 0
        dut.data_in_valid_i.value       = 0
        dut.data_out_ready_i.value      = 1
        dut.data_in_i.value             = 0
        dut.rsp_ready_i.value           = 1

        for _ in range(cycles):
            await RisingEdge(dut.clk_i)

        dut.rst_ni.value = 1
        await RisingEdge(dut.clk_i)

    async def run_encrypt(self, key: int, iv: int, aad: int,
                          plaintext_blocks: list,
                          ready_pattern: list[int] | None = None,
                          key_valid_delay: int = 0,
                          aad_valid_delay: int = 0,
                          payload_gaps: list[int] | None = None) -> tuple:
        """
        Encrypt NBLOCKS 128-bit blocks.
        Verify the complete output page: NBLOCKS ciphertext words, tag, AAD.
        Returns (ct_blocks, tag) for compatibility with existing tests.
        """
        await self._start_operation(
            mode=1,
            key=key,
            iv=iv,
            aad=aad,
            key_valid_delay=key_valid_delay,
            aad_valid_delay=aad_valid_delay,
        )
        stop = _StopEvent()
        mon_task = cocotb.start_soon(self._protocol_monitor(stop))
        cap_task = cocotb.start_soon(
            self._capture_output_stream(
                mode=1,
                aad=aad,
                ready_pattern=ready_pattern,
            )
        )
        drive_task = cocotb.start_soon(
            self._drive_payload(
                plaintext_blocks,
                mode=1,
                valid_gaps=payload_gaps,
            )
        )
        await drive_task
        output_words = await cap_task
        await self._wait_done(mode=1)
        stop.set()
        await mon_task

        tag = output_words[NBLOCKS]
        ct_blocks = output_words[:NBLOCKS]

        self.validate_encrypt_stream(output_words, aad=aad)
        await self._check_post_completion_quiescence()
        return ct_blocks, tag

    async def run_decrypt(self, key: int, iv: int, aad: int,
                          ct_blocks: list, exp_tag: int,
                          ready_pattern: list[int] | None = None,
                          key_valid_delay: int = 0,
                          aad_valid_delay: int = 0,
                          payload_gaps: list[int] | None = None) -> tuple:
        """
        Decrypt NBLOCKS 128-bit blocks.
        Returns (pt_blocks, tag_ok) where tag_ok is 0 or 1.
        """
        await self._start_operation(
            mode=0,
            key=key,
            iv=iv,
            aad=aad,
            exp_tag=exp_tag,
            key_valid_delay=key_valid_delay,
            aad_valid_delay=aad_valid_delay,
        )
        stop = _StopEvent()
        mon_task = cocotb.start_soon(self._protocol_monitor(stop))
        cap_task = cocotb.start_soon(
            self._capture_output_stream(
                mode=0,
                aad=aad,
                ready_pattern=ready_pattern,
            )
        )
        drive_task = cocotb.start_soon(
            self._drive_payload(
                ct_blocks,
                mode=0,
                valid_gaps=payload_gaps,
            )
        )
        await drive_task
        pt_blocks = await cap_task
        await self._wait_done(mode=0)
        stop.set()
        await mon_task
        await self._check_post_completion_quiescence()
        tag_ok = int(self.dut.rsp_auth_ok_o.value)
        return pt_blocks, tag_ok

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _clk_settle(self) -> None:
        """1 ns timer — mirrors the SV TB's #1 after posedge for NBA settle."""
        await Timer(1, unit='ns')

    async def _start_operation(
        self,
        *,
        mode: int,
        key: int,
        iv: int,
        aad: int,
        exp_tag: int = 0,
        key_valid_delay: int = 0,
        aad_valid_delay: int = 0,
    ) -> None:
        """
        Wait for command readiness, then hold the complete command stable
        until the ready/valid handshake accepts it.
        """
        dut = self.dut

        assert key_valid_delay >= 0
        assert aad_valid_delay >= 0

        while int(dut.cmd_ready_o.value) == 0:
            await RisingEdge(dut.clk_i)
            await self._clk_settle()

        for _ in range(max(key_valid_delay, aad_valid_delay)):
            await RisingEdge(dut.clk_i)
            await self._clk_settle()

        dut.cmd_mode_i.value      = mode
        dut.cmd_key_i.value       = key
        dut.cmd_iv_i.value        = iv
        dut.cmd_aad_i.value       = aad
        dut.cmd_exp_tag_i.value   = exp_tag
        dut.cmd_valid_i.value     = 1

        while True:
            await FallingEdge(dut.clk_i)
            assert int(dut.cmd_valid_i.value) == 1
            assert int(dut.cmd_mode_i.value) == mode
            assert int(dut.cmd_key_i.value) == key
            assert int(dut.cmd_iv_i.value) == iv
            assert int(dut.cmd_aad_i.value) == aad
            assert int(dut.cmd_exp_tag_i.value) == exp_tag
            ready = int(dut.cmd_ready_o.value)

            await RisingEdge(dut.clk_i)
            await self._clk_settle()
            if ready:
                break

        dut.cmd_valid_i.value = 0
        dut.rsp_ready_i.value = 0
        assert int(dut.cmd_ready_o.value) == 0
        assert int(dut.rsp_valid_o.value) == 0
        assert int(dut.rsp_error_o.value) == 0

    async def _drive_payload(
        self,
        blocks: list,
        mode: int = 1,
        valid_gaps: list[int] | None = None,
    ) -> None:
        """
        Present each block after its configured gap, then hold valid and the
        input data stable until ready.
        """
        dut = self.dut
        gaps = valid_gaps or [0]
        assert gaps and all(gap >= 0 for gap in gaps)

        for i, blk in enumerate(blocks):
            for _ in range(gaps[i % len(gaps)]):
                await RisingEdge(dut.clk_i)
                await self._clk_settle()

            dut.data_in_i.value       = blk
            dut.data_in_valid_i.value = 1

            while True:
                await FallingEdge(dut.clk_i)
                assert int(dut.data_in_valid_i.value) == 1
                assert int(dut.data_in_i.value) == blk
                ready = int(dut.data_in_ready_o.value)

                await RisingEdge(dut.clk_i)
                await self._clk_settle()
                if ready:
                    dut.data_in_valid_i.value = 0
                    break

    async def _capture_output_stream(
        self,
        *,
        mode: int,
        aad: int,
        ready_pattern: list[int] | None = None,
    ) -> list:
        """Capture and validate one complete top-level output transaction.

        Transfers are detected one FE after they fire: the RTL accepts a
        block at the posedge between two falling edges, so we check
        prev_valid && ready_driven (the ready we SET at the previous FE,
        which is what the RTL saw at the intervening posedge).
        """
        dut = self.dut
        expected_blocks = ENC_TOTAL_BLOCKS if mode else DEC_TOTAL_BLOCKS
        captured = []

        pattern = ready_pattern or [1]
        assert pattern and all(bit in (0, 1) for bit in pattern), (
            'ready_pattern must be a non-empty list containing only 0/1'
        )
        pattern_idx = 0
        ready_driven = pattern[pattern_idx]
        dut.data_out_ready_i.value = ready_driven

        prev_valid = 0
        prev_data  = 0
        prev_last  = 0

        while len(captured) < expected_blocks:
            await FallingEdge(dut.clk_i)

            valid = int(dut.data_out_valid_o.value)
            data  = int(dut.data_out_o.value)
            last  = int(dut.data_out_last_o.value)

            if prev_valid and ready_driven:
                transfer_idx = len(captured)
                captured.append(prev_data)

                is_last = transfer_idx == expected_blocks - 1
                assert prev_last == int(is_last), (
                    f'data_out_last_o={prev_last} on transfer '
                    f'{transfer_idx + 1}/{expected_blocks}'
                )

            prev_valid = valid
            prev_data  = data
            prev_last  = last

            pattern_idx = (pattern_idx + 1) % len(pattern)
            ready_driven = pattern[pattern_idx]
            dut.data_out_ready_i.value = ready_driven

        dut.data_out_ready_i.value = 1

        if mode:
            assert captured[NBLOCKS + 1] == aad, (
                'final encrypt output is not the latched AAD block'
            )
        return captured

    @staticmethod
    def validate_encrypt_stream(output_words: list, *, aad: int) -> None:
        """Check the non-payload words in a captured encrypt page."""
        streamed_aad = output_words[NBLOCKS + 1]

        assert streamed_aad == aad, (
            f'streamed AAD mismatch: '
            f'stream=0x{streamed_aad:0{BLOCK_HEX_DIGITS}x}, '
            f'input=0x{aad:0{BLOCK_HEX_DIGITS}x}'
        )

    async def _protocol_monitor(self, stop_event) -> None:
        """
        Enforce output-bus protocol invariants for one operation.

        P1 — valid must not drop unless a transfer was accepted last cycle.
        P2 — data and last must be stable while the transfer is stalled.

        Acceptance follows the top-level ready/valid handshake.
        """
        dut = self.dut
        prev_valid = 0
        prev_data  = 0
        prev_last  = 0

        while not stop_event.is_set():
            await RisingEdge(dut.clk_i)
            await self._clk_settle()

            valid = int(dut.data_out_valid_o.value)
            data  = int(dut.data_out_o.value)
            last  = int(dut.data_out_last_o.value)
            ready = int(dut.data_out_ready_i.value)
            accepted = prev_valid and ready

            if prev_valid and not accepted:
                assert valid == 1, (
                    'P1: data_out_valid_o dropped while ready was LOW'
                )
                assert data == prev_data, (
                    'P2: data_out_o changed while valid was stalled'
                )
                assert last == prev_last, (
                    'P2: data_out_last_o changed while valid was stalled'
                )

            prev_valid = valid
            prev_data  = data
            prev_last  = last

    async def _check_post_completion_quiescence(self, cycles: int = 10) -> None:
        """Fail if any output strobe fires within `cycles` clocks after page_done."""
        dut = self.dut
        for i in range(cycles):
            await RisingEdge(dut.clk_i)
            await self._clk_settle()
            assert int(dut.data_out_valid_o.value) == 0, (
                f'data_out_valid_o spuriously asserted {i + 1} cycle(s) after page_done'
            )
            assert int(dut.data_out_last_o.value) == 0, (
                f'data_out_last_o spuriously asserted {i + 1} cycle(s) after page_done'
            )
            assert int(dut.rsp_valid_o.value) == 0, (
                f'rsp_valid_o spuriously asserted {i + 1} cycle(s) after page_done'
            )

    async def _wait_done(self, mode: int | None = None) -> None:
        """Wait for the response handshake to complete."""
        dut = self.dut

        while True:
            await FallingEdge(dut.clk_i)
            assert int(dut.rsp_error_o.value) == 0
            if int(dut.rsp_valid_o.value) == 1:
                assert int(dut.cmd_ready_o.value) == 0
                break
            assert int(dut.cmd_ready_o.value) == 0

        dut.rsp_ready_i.value = 1

        while True:
            await FallingEdge(dut.clk_i)
            if int(dut.rsp_valid_o.value) == 0:
                assert int(dut.cmd_ready_o.value) == 1
                break
