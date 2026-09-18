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
| `docs/verification.md` | Suites, coverage of the matrix, recorded results |
| `docs/decisions.md` | Design decisions and their rationale |

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
vendored Secworks AES core under `rtl/third_party/secworks_aes/` keeps its own
BSD-2 licence from Secworks Sweden AB (see the `LICENSE` file in that folder).
