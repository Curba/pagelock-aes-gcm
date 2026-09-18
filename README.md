# aes_gcm_ip: parameterised AES-GCM page cipher

`aes_gcm_top` encrypts or decrypts one fixed-size page per command with
AES-GCM: `NBLOCKS` 128-bit payload blocks, a 96-bit IV, one 128-bit AAD block
and a 128-bit tag. On encrypt it streams the ciphertext followed by the tag
and the AAD so the output is a complete page image; on decrypt it streams the
plaintext and reports the authentication result in the response.

The block is configured at elaboration time:

| Knob | Values | Default |
|---|---|---|
| `KEY_W` | 128 or 256 | 128 |
| `PAGE_BYTES` | multiple of 16, at least 48 | 256 (14 payload blocks) |
| `WDT_TIMEOUT` | at least 1 | 4095 cycles |

Everything else follows from those (payload length, beat counts, key
schedule, key port width). Illegal combinations fail at elaboration with a
clear message. The 32-byte page trailer (tag + AAD) and the port list are the
same for both key sizes.

This is a standalone project: RTL, vendored AES core, benches, reference
vectors, build flow and documentation live in this folder and nothing outside
it is needed. It was derived from the AES-128 / 256-byte cipher block of the
`sec_cipher` security subsystem; at its default configuration it is
interface-compatible with that block and passes that block's regression
suites.

## Requirements

| Tool | Tested version | Needed for |
|---|---|---|
| Verilator | 5.052 | SV benches, default cocotb simulator, lint |
| Bender | any recent | Verilator file list from `Bender.yml` (or use `rtl/filelist.f`) |
| Python | 3.12+ | cocotb and the reference model |
| Icarus Verilog | 13.0 | optional: `SIM=icarus`, second tool in `make elab-check` |
| Verible | any recent | optional: style lint in `make lint` |

Python packages (installed into `.venv` by `make venv`):
`cocotb>=2.0`, `cryptography>=42`, `pycryptodomex>=3.20`, `pytest>=8`.

## Quick start

```
make venv && source .venv/bin/activate   # cocotb, cryptography, pycryptodomex
make lint                                # Verible + Verilator -Wall (both key sizes)
make elab-check                          # legal/illegal parameter sets, Verilator + Icarus
make conformance                         # Python reference vs NIST CAVP 128/256
make sim-all                             # 13 SystemVerilog benches (Verilator)
make cocotb-kat                          # cocotb KAT, default configuration
make cocotb KEY_W=256 PAGE_BYTES=4096 MODULE=test_aes_gcm_geometry
make matrix                              # full configuration matrix
```

See `GETTING_STARTED.md` for prerequisites and a walk-through.

## Layout

```
rtl/pkg/aes_gcm_pkg.sv        enums, fixed GCM widths, helper functions
rtl/aes_gcm_top.sv            top: parameters, guards, latches, datapath, glue
rtl/aes_gcm_fsm.sv            GCM control FSM, watchdog, key zeroisation
rtl/aes_gcm_oc.sv             output controller + response channel
rtl/aes_ghash.sv              GF(2^128) multiply-accumulate
rtl/third_party/secworks_aes  vendored AES core (BSD licence, read-only)
rtl/filelist.f                plain compile list (Bender-free)
rtl/verilator_waiver.vlt      lint waivers for the vendored core only
tb/sv/                        SystemVerilog benches
tb/cocotb/                    cocotb driver and suites
tb/conformance/               NIST CAVP reference validation
tb/elab/                      elaboration guard regression
tb/vectors/                   golden vectors (scripts/gen_gcm_vectors.py)
docs/                         see below
Bender.yml, Makefile          build entry points
```

## Documentation

| Document | Content |
|---|---|
| `GETTING_STARTED.md` | Tools, environment, first run, how to pick a configuration |
| `docs/architecture.md` | Module split, FSM states, what changes with each parameter |
| `docs/interface.md` | Port list, handshakes, operation sequences, timing |
| `docs/parameters.md` | Parameters, derived values, elaboration guards, watchdog semantics |
| `docs/page_format.md` | Byte layout of a page for any configuration, GCM inputs |

## Verification

Reference values come from the Python `cryptography` AESGCM model, which
`make conformance` validates against NIST CAVP AES-128 and AES-256 response
files (96-bit IV, 128-bit tag subset) and the McGrew-Viega test cases.

| Check | Command | Recorded result (2026-09-18) |
|---|---|---|
| Style and `-Wall` lint, both key sizes | `make lint` | clean |
| 8 legal + 12 illegal parameter sets, Verilator and Icarus | `make elab-check` | 40/40 |
| Reference model vs NIST CAVP 128/256 + McGrew-Viega | `make conformance` | 1508/1508 |
| 13 SystemVerilog benches incl. `tb_aes_gcm_param` (5 configurations) | `make sim-all` | 13/13 |
| cocotb KAT / negative (100) / random (128) / geometry (7) over 128 and 256-bit keys and 48, 256, 528, 4096-byte pages | `make matrix` | 22/22 |

Suites: `test_aes_gcm_kat` (known answers with ready patterns and input
gaps), `test_aes_gcm_negative` (tamper rejection, mode switching, command
injection, watchdog, reset timing), `test_aes_gcm_random` (seeded scenario
pool, `AES_RANDOM_COUNT` / `AES_RANDOM_SEED`), `test_aes_gcm_geometry` (beat
counts, page layout, key-size binding, key zeroisation, watchdog threshold and
margin, decrypt response timing). All derive the geometry from the
configuration under test, so any `KEY_W` / `PAGE_BYTES` can be run with
`make cocotb KEY_W=... PAGE_BYTES=... MODULE=...`.

Notes from the port:

- The output controller now gives a new command accept priority over the
  sticky FSM error flag. Without that, the command issued right after a
  watchdog abort without a reset left the controller idle and its output was
  never streamed; `test_watchdog_threshold` covers the recovery.
- Elaboration `$fatal` messages are single strings because Icarus Verilog
  does not accept format arguments in elaboration-time system tasks.
- The same watchdog default (4095) is used for both key sizes: AES-256 adds
  44 setup cycles and 20 cycles per block, leaving ample slack.
- Not covered: synthesis and timing, side-channel hardening, IV lengths other
  than 96 bits, multi-block AAD, truncated tags (the last three are rejected
  at elaboration).

## Interface in one picture

```
              cmd_valid/ready, mode, key[KEY_W], iv[96], aad[128], exp_tag[128]
  producer ───────────────────────────────────────────────────────────────►┐
              data_in_valid/ready, data_in[128]      (NBLOCKS beats)       │
  producer ───────────────────────────────────────────────────────────►    │
                                                                   aes_gcm_top
              data_out_valid/ready, data_out[128], last                    │
  consumer ◄───────────────────────────────────────────────────────────    │
              (encrypt: NBLOCKS CT + TAG + AAD, decrypt: NBLOCKS PT)       │
              rsp_valid/ready, auth_ok, error                              │
  consumer ◄───────────────────────────────────────────────────────────────┘
```

## Licence

This project is licensed under the Apache License 2.0 (see `LICENSE`). The
vendored Secworks AES core under `rtl/third_party/secworks_aes/` is not
relicensed: it stays under its original BSD-2-Clause licence (copyright
Joachim Strömbergson / Secworks Sweden AB, see the `LICENSE` file and the
headers in that folder). BSD-2-Clause is compatible with Apache-2.0; keep
that folder's licence file and file headers intact when redistributing.
