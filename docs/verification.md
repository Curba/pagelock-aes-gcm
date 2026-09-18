# Verification

Everything below runs from the repository root. Results are from the
recorded run on 2026-09-18 with Verilator 5.052, Icarus Verilog 13.0,
cocotb 2.0 and the `cryptography` package validated by `make conformance`.

## Reference model

All expected values come from the Python `cryptography` AESGCM implementation.
`tb/conformance/nist_ref_validation.py` (`make conformance`) validates that
model against NIST CAVP response files for AES-128 and AES-256 (encrypt and
decrypt, 96-bit IV / 128-bit tag subset, 375 vectors each) and the
McGrew-Viega test cases TC1-TC4 (AES-128) and TC13-TC16 (AES-256).

Result: 1508 vectors, 1508 passed, 0 failed.

## Static checks

| Target | What | Result |
|---|---|---|
| `make lint` | Verible style rules (`.verible_lint.rules`) on the block RTL; Verilator `-Wall` lint of `aes_gcm_top` for `KEY_W=128` and `KEY_W=256` (vendored core waived only) | clean |
| `make elab-check` | `tb/elab/run_elab_checks.py`: 8 legal and 12 illegal parameter sets, each elaborated with Verilator and Icarus; legal sets must elaborate cleanly, illegal sets must fail with the documented message | 40/40 |

## SystemVerilog benches (`make sim-all`, Verilator, default configuration)

These are the original sec_cipher cipher benches, unchanged apart from the
package import and vector paths, plus the new multi-configuration bench.

| Bench | Level | Covers |
|---|---|---|
| `tb_aes_ghash` | unit | GHASH against SP 800-38D test cases |
| `tb_aes_gcm_fsm` | unit | FSM sequencing with a behavioural AES stub |
| `tb_aes_gcm_quickfix` | unit | Watchdog, sticky error, key zeroisation, bus latch |
| `tb_aes_gcm_timeout` | unit | Timeout and recovery at the top |
| `tb_output_fsm_happy` | output | Encrypt and decrypt output sequencing, tag/AAD append, `last` |
| `tb_output_fsm_backpressure` | output | Stall in the payload stream |
| `tb_aes_smoke` | integration | Vendored AES core sanity |
| `tb_aes_gcm_top` | integration | Golden-vector encrypt / decrypt / tamper with a streaming producer |
| `tb_aes_gcm_roundtrip` | integration | Encrypt, decrypt, tamper round trip |
| `tb_aes_gcm_backpressure` | integration | Stalls mid-CT, on the tag beat, on the AAD beat, during decrypt |
| `tb_aes_gcm_deep_backpressure` | integration | Long stall, valid held independent of ready |
| `tb_v2_contract` | integration | Black-box check of the v2 command / data / response contract |
| `tb_aes_gcm_param` (new) | integration | Five configurations side by side: AES-256/64 B, AES-128/48 B, AES-256/528 B, AES-256/256 B, AES-128/256 B. Encrypt against golden vectors, decrypt of the page, tampered decrypt, beat counts, `last` placement, response timing, no beats after response, periodic output back-pressure. Prints setup latency, cadence and total cycles. |

Result: 13/13 passed (`tb_aes_gcm_param`: 70 checks).

`tb_oc_ready_skew.sv` from the original tree is not included; see
`docs/decisions.md` item 14.

## cocotb suites (`tb/cocotb`, `make cocotb MODULE=... KEY_W=... PAGE_BYTES=...`)

All suites derive the geometry from the environment, so the same code runs on
every configuration. The driver enforces the stream protocol on every
operation: valid never drops while stalled, data and `last` stable while
stalled, exact beat counts, `last` only on the final beat, AAD replay on
encrypt, 10-cycle quiescence after each response, response handshake and
`cmd_ready_o` behaviour.

| Suite | Scenarios | Covers |
|---|---|---|
| `test_aes_gcm_kat` | 5 vectors x encrypt, decrypt, tamper | Known answers against the reference with five output-ready patterns, input gaps and command delays |
| `test_aes_gcm_negative` | 100 | Tampered AAD / tag / CT / IV / key rejection, mode switching without reset, mid-operation command injection, double command, early valid, watchdog starvation and recovery, reset held 1/2/4/8 cycles, same-key bursts, zero expected tag |
| `test_aes_gcm_random` | 128 of a 1923-scenario pool (seed 2026, `AES_RANDOM_COUNT` / `AES_RANDOM_SEED` selectable) | Encrypt-only, round trips with and without reset, interleaved operations, back-to-back encrypts, key reuse, determinism, single-bit corner cases, mid-operation reset recovery, complementary plaintexts; random ready patterns, input gaps and command delays per operation |
| `test_aes_gcm_geometry` (new) | 7 tests | Exact input / output beat counts and `last` index for both directions; no input accepted after the final block; byte-exact page layout CT / TAG / AAD; output matches AES-`KEY_W` and not the other key size on the same key bits; key register zeroised after expansion; watchdog fires `WDT_TIMEOUT + 2` cycles after accept when starved, and the next command works without a reset; a legal long input gap does not trigger it; decrypt response arrives after tag finalisation |

## Configuration matrix (`make matrix`, Verilator)

| KEY_W | PAGE_BYTES | NBLOCKS | kat | negative | random | geometry |
|---:|---:|---:|:-:|:-:|:-:|:-:|
| 128 | 256 | 14 | pass | pass (100/100) | pass (128/128) | pass |
| 256 | 256 | 14 | pass | pass (100/100) | pass (128/128) | pass |
| 128 | 48 | 1 | pass | pass (100/100) | - | pass |
| 256 | 48 | 1 | pass | - | - | pass |
| 128 | 528 | 31 | pass | - | - | pass |
| 256 | 528 | 31 | pass | - | - | pass |
| 128 | 4096 | 254 | pass | - | - | pass |
| 256 | 4096 | 254 | pass | - | pass (128/128) | pass |

22 matrix entries, 22 passed. The Icarus path was additionally checked with
`make cocotb-kat SIM=icarus KEY_W=256 PAGE_BYTES=64` (3/3).

Why these points: 48 bytes is the smallest legal page (one payload block,
`BLK_W = 1`); 528 is a non-power-of-two NAND-style page; 4096 exercises a
wide block counter and long operations; 256 is the original geometry. Both
key sizes are run at every page size for KAT and geometry; the long negative
and random suites run at the original geometry for both key sizes, at the
smallest page for AES-128, and the random suite at the largest page for
AES-256.

## Measured timing

See the timing table in `docs/interface.md`. Key figures: setup 256 (AES-128)
/ 300 (AES-256) cycles, cadence 183 / 203 cycles per block, decrypt response
261 cycles after the last plaintext beat, watchdog abort `WDT_TIMEOUT + 2`
cycles after accept when starved.

## Regenerating vectors and reports

- `make vectors` rewrites `tb/vectors/ct.hex` and `tag.hex` (byte-identical
  to the sec_cipher originals). `python3 scripts/gen_gcm_vectors.py --all`
  also writes the sets used by `tb_aes_gcm_param`.
- The negative and random suites write a text report per configuration to
  `build/reports/`.
- `make matrix` writes one log per entry to `build/matrix_<KEY_W>_<PAGE_BYTES>_<suite>.log`.

## Not covered

- Synthesis and timing closure: no netlist or STA was run in this project.
- Side-channel or fault-injection hardening (out of scope by design).
- IV lengths other than 96 bits, multi-block AAD, truncated tags (rejected at
  elaboration).
- Consumers that never accept the tag / AAD beats or the response: there is no
  timeout on those paths, as in the original block.
