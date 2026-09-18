# Architecture

```
aes_gcm_top  (parameters: KEY_W, PAGE_BYTES, WDT_TIMEOUT)
├── aes_gcm_fsm    GCM sequencing: key schedule, H, J0, AAD, NBLOCKS payload
│                  blocks, length block, tag; watchdog; key zeroisation
├── aes_core       Secworks iterative AES (vendored, read-only), keylen tied
│                  from KEY_W, always forward cipher (CTR mode)
├── aes_ghash      Bit-serial GF(2^128) multiply-accumulate, 128 cycles/block
└── aes_gcm_oc     Output controller: streams payload beats, appends TAG and
                   AAD on encrypt, drives `last`, owns the response channel
```

`rtl/pkg/aes_gcm_pkg.sv` holds the state enums, the algorithm-fixed widths and
the helper functions used by the elaboration guards.

## Responsibilities

**aes_gcm_top** owns the command latches for mode, AAD and expected tag, the
`cmd_ready_o` equation, the response-pending flag, the CTR datapath
(`ciphertext = AES(counter) XOR data`) and the GHASH source mux (GHASH always
sees ciphertext: freshly computed on encrypt, incoming on decrypt). It also
adapts the key to the Secworks core: for `KEY_W = 128` the key sits in the
upper 128 bits of the 256-bit core port with `keylen = 0`; for `KEY_W = 256`
the full key is passed with `keylen = 1`.

**aes_gcm_fsm** latches key and IV itself so the key can be zeroised inside
the FSM once the core has expanded it. States, in order:

| State | Work | Duration (cycles) |
|---|---|---|
| `ST_IDLE` | Wait for accept; latch key, IV, mode | - |
| `ST_KEY_INIT` | `init` to the core, wait for key expansion, zeroise key register | ~12 (128) / ~16 (256) |
| `ST_GEN_H` | Encrypt `0^128`, latch H | ~55 (128) / ~75 (256) |
| `ST_PREP_J0` | `ghash_init`, load H into GHASH | 1 |
| `ST_ENC_J0` | Encrypt `{IV, 1}`, latch EJ0, capture AAD | ~55 (128) / ~75 (256) |
| `ST_PROC_AAD` | One GHASH block | ~130 |
| `ST_PROC_PAYLOAD` | Per block: accept input, AES(counter), emit beat, GHASH block | 183 (128) / 203 (256) per block |
| `ST_FINALIZE` | GHASH length block, `tag = GHASH XOR EJ0`, compare on decrypt, `done` | ~130 |

Setup (accept to first `data_in_ready_o`) totals 256 cycles for AES-128 and
300 for AES-256, measured by `tb_aes_gcm_param`.

The payload loop is a three-phase handshake per block: (1) accept the input
beat and fire `aes_next`, (2) when the AES result is valid, present the output
beat and, on the edge the consumer accepts it, feed GHASH, (3) when GHASH is
ready again, advance the counter and block index. Phase 2 keeps
`block_out_valid_o` independent of `data_out_ready_i`, and the GHASH feed is
gated on the consumer's acceptance so GHASH and the consumer always see the
same block. `NBLOCKS` is the only parameter that reaches the loop: the block
index width is `$clog2(NBLOCKS + 1)` and the length block is computed from it.

**aes_ghash** is unchanged from the original block except for dropping its
package dependency; it is 128 bits wide by definition.

**aes_gcm_oc** has four states: `OC_IDLE`, `OC_PASS` (payload beats from the
FSM), `OC_TAG`, `OC_AAD`. Decrypt goes `PASS -> IDLE` on `done`; encrypt goes
`PASS -> TAG -> AAD -> IDLE`, one beat per state. It registers `rsp_valid`
(armed on `done` for decrypt, on the AAD transfer for encrypt, immediately on
error) and `rsp_error`, and guards against re-arming from the sticky FSM
`done`/`err` flags with a one-shot latch that clears on the next accept. The
widths are parameters but the sequence does not depend on `KEY_W`, because
tag and AAD are one beat each in every supported configuration.

## What changes with KEY_W

| Item | 128 | 256 |
|---|---|---|
| `cmd_key_i` width | 128 | 256 |
| Secworks `key` port | `{key, 128'd0}` | `key` |
| Secworks `keylen` | 0 (10 rounds) | 1 (14 rounds) |
| FSM key register | 128 | 256 |
| Setup phase (accept to first input) | 256 cycles | 300 cycles |
| Payload block cadence | 183 cycles | 203 cycles |
| Page trailer, AAD, tag, IV, output controller, beat counts | identical | identical |

The iterative Secworks core spends a fixed number of cycles per round, so the
four extra AES-256 rounds show up as about 20 cycles per AES invocation: one
per payload block, and two (H and J0) plus a longer key schedule in the setup
phase. Nothing in the handshakes or the output format changes.

## What changes with PAGE_BYTES

`NBLOCKS = (PAGE_BYTES - 32) / 16` sets the payload loop count, the block
index width, the GCM length block and the expected beat counts. Nothing else
in the design depends on the page size; the 32-bit CTR field already covers
any page size the guards allow.

## Reset and clocking

Single clock domain. All flip-flops use asynchronous active-low reset with a
defined reset value. No latches, no combinational loops, no clock gating.
`unique case` on every state decode. The design lints clean under Verilator
`-Wall` (vendored core excluded via `rtl/verilator_waiver.vlt`) and Verible
with the rule set in `.verible_lint.rules`.
