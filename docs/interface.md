# Interface

All signals are synchronous to `clk_i`. Reset is `rst_ni`, active-low,
asynchronous assert, synchronous deassert. Every channel is a ready/valid
handshake: a transfer happens on a rising edge where `valid` and `ready` are
both high; `valid` never depends combinationally on `ready`; payload signals
are stable while `valid` is high and `ready` is low.

## Port list

Widths in bits. `KEY_W`, `IV_W`, `AAD_W`, `TAG_W`, `DATA_W` are the
parameters described in `docs/parameters.md` (only `KEY_W` varies in practice).

### Clock and reset

| Signal | Dir | Width | Description |
|---|---|---|---|
| `clk_i` | in | 1 | Clock |
| `rst_ni` | in | 1 | Active-low reset |

### Command channel

All fields are captured on the accept edge (`cmd_valid_i && cmd_ready_o`). The
producer may change any field the cycle after.

| Signal | Dir | Width | Description |
|---|---|---|---|
| `cmd_valid_i` | in | 1 | Command present. Hold until `cmd_ready_o`. |
| `cmd_ready_o` | out | 1 | High when the FSM is idle, the output controller is idle and no response is pending or being raised. Low from the accept edge until the response of that command has been acknowledged. |
| `cmd_mode_i` | in | 1 | 1 = encrypt, 0 = decrypt. |
| `cmd_key_i` | in | `KEY_W` | AES key. Latched in the FSM at accept and zeroised there once key expansion is complete (about 12 cycles for AES-128, 16 for AES-256). |
| `cmd_iv_i` | in | 96 | IV. Latched in the FSM at accept. |
| `cmd_aad_i` | in | 128 | The single AAD block. Latched in the top at accept, also replayed as the final encrypt output beat. |
| `cmd_exp_tag_i` | in | 128 | Decrypt: expected tag. Ignored on encrypt. Latched at accept. |

### Data input stream

| Signal | Dir | Width | Description |
|---|---|---|---|
| `data_in_valid_i` | in | 1 | Input block present. |
| `data_in_ready_o` | out | 1 | Block accepted on this edge. First asserted after the setup phase. |
| `data_in_i` | in | 128 | Plaintext (encrypt) or ciphertext (decrypt). |

Exactly `NBLOCKS` beats per command. `data_in_ready_o` is never asserted once
the `NBLOCKS`-th beat has been accepted, so a producer that offers more data
simply stalls; the block does not consume or count extra beats. Offering fewer
beats stalls the operation until the watchdog aborts it.

### Data output stream

| Signal | Dir | Width | Description |
|---|---|---|---|
| `data_out_valid_o` | out | 1 | Output beat present. Held until accepted. |
| `data_out_ready_i` | in | 1 | Consumer accepts on this edge. Per-cycle back-pressure is supported anywhere in the stream. |
| `data_out_o` | out | 128 | Output beat. Stable while valid. |
| `data_out_last_o` | out | 1 | High with the final beat of the operation (AAD beat on encrypt, final plaintext beat on decrypt). |

Encrypt produces `NBLOCKS + 2` beats (CT, TAG, AAD); decrypt produces
`NBLOCKS` beats. See `docs/page_format.md`.

### Response channel

| Signal | Dir | Width | Description |
|---|---|---|---|
| `rsp_valid_o` | out | 1 | Response present. Held until `rsp_ready_i`. |
| `rsp_ready_i` | in | 1 | Consumer acknowledges. |
| `rsp_auth_ok_o` | out | 1 | Decrypt: 1 if the computed tag equals `cmd_exp_tag_i`. Encrypt: always 1. Valid while `rsp_valid_o`. |
| `rsp_error_o` | out | 1 | 1 if the operation was aborted by the watchdog or an illegal FSM state. Cleared by the next accepted command. |

Exactly one response per accepted command, including aborted ones. The next
command is not accepted until the response has been acknowledged. On decrypt
the response is held back until tag finalisation even if `rsp_ready_i` is
already high, so `rsp_auth_ok_o` is always meaningful when `rsp_valid_o` is
seen.

## Operation sequence

Encrypt:

1. Assert `cmd_valid_i` with mode 1, key, IV and AAD; hold until `cmd_ready_o`.
2. Present `NBLOCKS` plaintext beats; each is accepted when `data_in_ready_o`
   is high (first one 256 cycles after accept for AES-128, 300 for AES-256;
   then one every 183 cycles for AES-128 and 203 for AES-256 with an
   always-ready consumer).
3. Accept `NBLOCKS` ciphertext beats, the tag beat and the AAD beat
   (`data_out_last_o`).
4. Acknowledge `rsp_valid_o` with `rsp_ready_i`. `cmd_ready_o` returns high.

Decrypt:

1. Assert `cmd_valid_i` with mode 0, key, IV, AAD and the expected tag.
2. Present `NBLOCKS` ciphertext beats.
3. Accept `NBLOCKS` plaintext beats (`data_out_last_o` on the final one). Hold
   them if unauthenticated data must not be exposed.
4. Wait for `rsp_valid_o` (about 261 cycles after the last plaintext beat),
   read `rsp_auth_ok_o` and `rsp_error_o`, acknowledge with `rsp_ready_i`.

Error (watchdog):

1. The FSM returns to idle, the output controller drops any in-flight beat.
2. `rsp_valid_o` asserts with `rsp_error_o = 1`; acknowledge it.
3. The next command works normally without a reset (regression:
   `test_watchdog_threshold` in `tb/cocotb/test_aes_gcm_geometry.py`).

## Timing summary (always-ready consumer, clock cycles)

| Event | AES-128 | AES-256 |
|---|---:|---:|
| Command accept to first `data_in_ready_o` | 256 | 300 |
| Payload block cadence (input to input) | 183 | 203 |
| Final plaintext beat to decrypt `rsp_valid_o` | 261 | 261 |
| Encrypt `rsp_valid_o` after AAD beat accepted | 1 | 1 |
| Command accept to response, 256-byte page (14 blocks), encrypt | 2 951 | 3 275 |
| Command accept to response, 256-byte page (14 blocks), decrypt | 2 949 | 3 273 |
| Command accept to response, 528-byte page (31 blocks), encrypt | - | 6 758 |
| Command accept to response, 48-byte page (1 block), encrypt | 576 | - |
| Command accept to response, 64-byte page (2 blocks), encrypt | - | 839 |
| Input starvation to error response | `WDT_TIMEOUT + 2` | `WDT_TIMEOUT + 2` |

Measured by `tb_aes_gcm_param` (printed as `INFO` lines, always-ready
consumer) and the cocotb geometry suite. AES-256 costs four extra rounds per
AES invocation with this iterative core: about 20 cycles per payload block and
44 cycles in the setup phase (two AES invocations plus a longer key schedule).
Per-page time is close to `390 + 183 * NBLOCKS` cycles for AES-128 and
`435 + 203 * NBLOCKS` for AES-256.

## Compatibility with the sec_cipher v2 contract

The port list is identical to `aes_gcm_top` in the sec_cipher repository at
its default configuration (`KEY_W = 128`, `PAGE_BYTES = 256`): same names,
same widths, same handshakes, same beat counts and same response timing. The
original SystemVerilog and cocotb suites run unmodified apart from module
package imports and vector paths. The one behavioural difference is the
output-controller recovery fix described in the README (Verification), which
only affects the command issued right after a watchdog abort without a reset.
