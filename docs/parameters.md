# Parameters and configuration rules

`aes_gcm_top` is configured entirely at elaboration time. There is no runtime
configuration port: every geometry decision is a parameter, every illegal
combination is rejected by a `$fatal` in a generate block, and the derived
values are exposed as read-only `localparam`s so integrators and testbenches
can reference them.

## User parameters

| Parameter | Default | Legal values | Effect |
|---|---|---|---|
| `KEY_W` | 128 | 128, 256 | AES key width. Sets the `cmd_key_i` port width, the Secworks `keylen` select (10 vs 14 rounds) and the key register width in the FSM. |
| `PAGE_BYTES` | 256 | multiple of 16, at least 48 | Total page size in bytes including the 32-byte trailer. Payload per command = `PAGE_BYTES - 32`. |
| `WDT_TIMEOUT` | `gcm_wdt_timeout_default(KEY_W)` = 4095 | at least 1 | Watchdog threshold in clock cycles. See "Watchdog semantics" below. |
| `IV_W` | 96 | 96 only | Exists for readability and read-back. Only the 96-bit IV construction `J0 = IV || 0^31 || 1` is implemented. |
| `AAD_W` | 128 | 128 only | One AAD block for both key sizes. |
| `TAG_W` | 128 | 128 only | Full-length GCM tag. |
| `DATA_W` | 128 | 128 only | AES block width; input, output and GHASH word width. |

`KEY_W` and `PAGE_BYTES` are the only knobs you normally set. Everything the
key size implies (core key length select, key port width, FSM key register,
watchdog default) follows from `KEY_W` inside the RTL; there is no second
parameter to keep consistent with it.

## Derived values (read-only)

| Localparam | Formula | 128 / 256 B page | 256 / 48 B | 128 / 4096 B |
|---|---|---|---|---|
| `META_BYTES` | `(TAG_W + AAD_W) / 8` | 32 | 32 | 32 |
| `PAYLOAD_BYTES` | `PAGE_BYTES - META_BYTES` | 224 | 16 | 4064 |
| `NBLOCKS` | `PAYLOAD_BYTES / 16` | 14 | 1 | 254 |
| `ENC_OUT_BLOCKS` | `NBLOCKS + 2` | 16 | 3 | 256 |
| `DEC_OUT_BLOCKS` | `NBLOCKS` | 14 | 1 | 254 |

They are declared in the parameter port list of `aes_gcm_top` as
`localparam`, so `aes_gcm_top #(.KEY_W(256), .PAGE_BYTES(64))` cannot override
them and a testbench can read `dut.NBLOCKS`.

## Elaboration guards

All checks live at the top of `rtl/aes_gcm_top.sv` (and are repeated in
`aes_gcm_fsm` / `aes_gcm_oc` so the sub-modules are safe when instantiated on
their own). Each violated rule aborts elaboration with the message below.

| Rule | Message |
|---|---|
| `KEY_W` in {128, 256} | `aes_gcm_top: KEY_W must be 128 or 256` |
| `DATA_W == 128` | `aes_gcm_top: DATA_W must be 128 (AES block width)` |
| `IV_W == 96` | `aes_gcm_top: only the 96-bit IV construction is implemented (IV_W must be 96)` |
| `AAD_W == 128` | `aes_gcm_top: AAD_W is fixed at 128 bits (one block) for every key size` |
| `TAG_W == 128` | `aes_gcm_top: TAG_W is fixed at 128 bits` |
| `PAGE_BYTES % 16 == 0` | `aes_gcm_top: PAGE_BYTES must be a multiple of 16` |
| `PAGE_BYTES >= 48` | `aes_gcm_top: PAGE_BYTES must be at least 48 (TAG + AAD + one payload block)` |
| `WDT_TIMEOUT >= 1` | `aes_gcm_top: WDT_TIMEOUT must be at least 1` |
| `NBLOCKS <= 2^32 - 3` (FSM) | `aes_gcm_fsm: NBLOCKS exceeds the GCM counter limit (2^32 - 2)` |

The messages are deliberately plain strings (no format arguments) because
Icarus Verilog only accepts a single string argument in elaboration-time
system tasks. Verilator reports them as `%Warning-USERFATAL` and exits with an
error; Icarus prints `FATAL:` and stops. `make elab-check` runs every rule
against both tools (`tb/elab/run_elab_checks.py`).

The upper bound on `PAGE_BYTES` is the GCM counter limit, which no realistic
page reaches. Practically, the block counter (`$clog2(NBLOCKS + 1)` bits) and
the 32-bit CTR field are the only structures that grow with the page, so large
pages cost almost nothing in area. Simulation time grows linearly with
`NBLOCKS` (183 cycles per block for AES-128, 203 for AES-256).

## Watchdog semantics

The watchdog counter is cleared while the FSM is idle and on every accepted
payload input block. It counts in every other cycle of an operation,
including the setup phase (key schedule, H, J0, AAD), the time spent waiting
for the output consumer, and finalisation. When it reaches `WDT_TIMEOUT` the
FSM returns to idle, the output controller is reset, and a response with
`rsp_error_o = 1` is raised. The response must be acknowledged like any other.

Consequences for integrators:

- The first payload block must arrive within roughly `WDT_TIMEOUT - setup`
  cycles of the command accept (setup is 256 cycles for AES-128 and 300 for
  AES-256, see `docs/interface.md`).
- Later payload blocks must arrive within roughly `WDT_TIMEOUT - 180` cycles
  of the previous block being accepted (the AES and GHASH work for that block
  is about 160 cycles for AES-128 and 180 for AES-256).
- An output stall on a payload beat longer than roughly `WDT_TIMEOUT - 180`
  cycles also aborts the operation.
- The trailing TAG and AAD beats and the response handshake are not timed:
  a consumer that never accepts them stalls the block until reset. This is
  unchanged from the original sec_cipher block.

AES-256 adds 44 cycles to the setup phase and 20 cycles per payload block,
which leaves well over 3 700 cycles of slack under the default threshold, so
the same default of 4095 is used for both key sizes. The default is produced by `gcm_wdt_timeout_default()` in
`rtl/pkg/aes_gcm_pkg.sv`, which is the single place to change if a project
needs a different per-key-size default. Any instance can also override
`WDT_TIMEOUT` directly.

## Selecting a configuration

SystemVerilog instantiation:

```systemverilog
aes_gcm_top #(
  .KEY_W      (256),
  .PAGE_BYTES (528)      // 31 payload blocks + 16 B tag + 16 B AAD
) u_cipher ( ... );
```

Verilator command line (lint or build):

```
verilator --top-module aes_gcm_top -GKEY_W=256 -GPAGE_BYTES=528 -f rtl/filelist.f
```

Icarus Verilog:

```
iverilog -g2012 -s aes_gcm_top -P aes_gcm_top.KEY_W=256 -P aes_gcm_top.PAGE_BYTES=528 -f rtl/filelist.f
```

cocotb (`tb/cocotb/Makefile` forwards the same numbers to the simulator and to
the Python driver):

```
make cocotb KEY_W=256 PAGE_BYTES=528 MODULE=test_aes_gcm_geometry
```
