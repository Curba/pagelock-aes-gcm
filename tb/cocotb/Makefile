# cocotb testbench Makefile for aes_gcm_top.
#
#   make                                   KAT suite, default config, Verilator
#   make SIM=icarus                        same on Icarus Verilog
#   make KEY_W=256 PAGE_BYTES=4096         AES-256, 4 KiB page (254 payload blocks)
#   make MODULE=test_aes_gcm_negative      negative / robustness suite
#   make MODULE=test_aes_gcm_random        constrained random (AES_RANDOM_COUNT, AES_RANDOM_SEED)
#   make MODULE=test_aes_gcm_geometry      block-count / page-layout / watchdog checks
#
# The DUT parameters are passed to the simulator and exported to Python as
# AES_KEY_W / AES_PAGE_BYTES / AES_WDT_TIMEOUT so the driver derives the
# geometry from the same numbers.

SIM          ?= verilator
TOPLEVEL_LANG = verilog
TOPLEVEL      = aes_gcm_top
MODULE       ?= test_aes_gcm_kat
COCOTB_TEST_MODULES = $(MODULE)

KEY_W       ?= 128
PAGE_BYTES  ?= 256
WDT_TIMEOUT ?= 4095
WAVES       ?= 0

CFG := k$(KEY_W)_p$(PAGE_BYTES)_w$(WDT_TIMEOUT)
SIM_BUILD           = $(abspath ../../build/cocotb/$(SIM)/$(CFG)/sim_build)
COCOTB_RESULTS_FILE = $(abspath ../../build/cocotb/$(SIM)/$(CFG)/results_$(MODULE).xml)

export AES_KEY_W       = $(KEY_W)
export AES_PAGE_BYTES  = $(PAGE_BYTES)
export AES_WDT_TIMEOUT = $(WDT_TIMEOUT)

COCOTB_HDL_TIMEUNIT      = 1ns
COCOTB_HDL_TIMEPRECISION = 1ps

RTL := $(abspath ../../rtl)
VERILOG_SOURCES = \
    $(RTL)/pkg/aes_gcm_pkg.sv \
    $(RTL)/third_party/secworks_aes/src/rtl/aes_sbox.v \
    $(RTL)/third_party/secworks_aes/src/rtl/aes_inv_sbox.v \
    $(RTL)/third_party/secworks_aes/src/rtl/aes_key_mem.v \
    $(RTL)/third_party/secworks_aes/src/rtl/aes_encipher_block.v \
    $(RTL)/third_party/secworks_aes/src/rtl/aes_decipher_block.v \
    $(RTL)/third_party/secworks_aes/src/rtl/aes_core.v \
    $(RTL)/aes_ghash.sv \
    $(RTL)/aes_gcm_fsm.sv \
    $(RTL)/aes_gcm_oc.sv \
    $(RTL)/aes_gcm_top.sv

ifeq ($(SIM),icarus)
  COMPILE_ARGS += -g2012 \
    -P $(TOPLEVEL).KEY_W=$(KEY_W) \
    -P $(TOPLEVEL).PAGE_BYTES=$(PAGE_BYTES) \
    -P $(TOPLEVEL).WDT_TIMEOUT=$(WDT_TIMEOUT)
  # Treat undriven signals as 0 rather than X so Python .value reads work.
  export COCOTB_RESOLVE_X = RANDOM
else ifeq ($(SIM),verilator)
  EXTRA_ARGS += -GKEY_W=$(KEY_W) -GPAGE_BYTES=$(PAGE_BYTES) -GWDT_TIMEOUT=$(WDT_TIMEOUT) \
    -Wno-TIMESCALEMOD -Wno-WIDTHEXPAND -Wno-WIDTHTRUNC -Wno-UNOPTFLAT -Wno-PINMISSING
  ifeq ($(WAVES),1)
    EXTRA_ARGS += --trace-fst --trace-structs
  endif
else
  $(error SIM must be verilator or icarus)
endif

include $(shell cocotb-config --makefiles)/Makefile.sim
