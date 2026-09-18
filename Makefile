# aes_gcm_ip top-level Makefile
# Bender drives the SV file list; cocotb has its own Makefile under tb/cocotb.
#
# Quick start:
#   make lint                 Verible + Verilator lint (both key sizes)
#   make sim-all              all SystemVerilog benches, default config, Verilator
#   make cocotb               cocotb KAT suite, default config (KEY_W=128 PAGE_BYTES=256)
#   make cocotb KEY_W=256 PAGE_BYTES=4096 MODULE=test_aes_gcm_random
#   make matrix               full configuration matrix (see docs/verification.md)
#   make elab-check           illegal parameter sets must fail at elaboration
#   make conformance          NIST CAVP + McGrew-Viega sweep of the Python reference

BENDER    := bender
VERILATOR := verilator
VERIBLE   := verible-verilog-lint
PYTHON    ?= python3
SURFER    := surfer
BUILD_DIR := build

# cocotb configuration knobs (forwarded to tb/cocotb/Makefile)
SIM         ?= verilator
KEY_W       ?= 128
PAGE_BYTES  ?= 256
WDT_TIMEOUT ?= 4095
MODULE      ?= test_aes_gcm_kat

RTL_FILES := rtl/pkg/aes_gcm_pkg.sv rtl/aes_ghash.sv rtl/aes_gcm_fsm.sv rtl/aes_gcm_oc.sv rtl/aes_gcm_top.sv

SV_TBS := tb_aes_ghash tb_aes_gcm_fsm tb_aes_gcm_timeout tb_aes_gcm_quickfix \
          tb_output_fsm_happy tb_output_fsm_backpressure tb_aes_smoke \
          tb_aes_gcm_top tb_aes_gcm_roundtrip tb_aes_gcm_backpressure \
          tb_aes_gcm_deep_backpressure tb_v2_contract tb_aes_gcm_param

VL_WARN := -Wno-TIMESCALEMOD -Wno-WIDTHEXPAND -Wno-WIDTHTRUNC -Wno-UNOPTFLAT -Wno-PINMISSING

.PHONY: help
help:
	@echo "aes_gcm_ip build targets"
	@echo ""
	@echo "  Setup"
	@echo "    make venv               create .venv with cocotb, cryptography, pycryptodomex"
	@echo ""
	@echo "  Lint"
	@echo "    make lint               Verible style lint + Verilator lint for KEY_W=128 and 256"
	@echo ""
	@echo "  SystemVerilog benches (Verilator, default configuration)"
	@echo "    make sim TB=<name>      compile + run one bench, wave in build/<name>/wave.fst"
	@echo "    make sim-all            run all SV benches"
	@echo "    make wave TB=<name>     open the .fst in Surfer"
	@echo ""
	@echo "  cocotb (SIM=verilator|icarus, KEY_W=128|256, PAGE_BYTES=48..., WDT_TIMEOUT=...)"
	@echo "    make cocotb [MODULE=test_aes_gcm_kat|test_aes_gcm_negative|test_aes_gcm_random|test_aes_gcm_geometry]"
	@echo "    make cocotb-kat / cocotb-negative / cocotb-random / cocotb-geometry"
	@echo "    make matrix             the documented configuration matrix"
	@echo ""
	@echo "  Other"
	@echo "    make elab-check         illegal parameter sets are rejected at elaboration"
	@echo "    make conformance        NIST CAVP (128 + 256) sweep of the Python reference model"
	@echo "    make vectors            regenerate tb/vectors/*.hex golden vectors"
	@echo "    make clean"

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
.PHONY: venv
venv:
	$(PYTHON) -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt
	@echo "Activate with: source .venv/bin/activate"

# ---------------------------------------------------------------------------
# File list
# ---------------------------------------------------------------------------
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/sim.f: Bender.yml Makefile | $(BUILD_DIR)
	$(BENDER) script verilator -t simulation -t test > $@

# ---------------------------------------------------------------------------
# Lint
# ---------------------------------------------------------------------------
.PHONY: lint lint-verible lint-verilator
lint: lint-verible lint-verilator

lint-verible:
	$(VERIBLE) --rules_config=.verible_lint.rules --lint_fatal $(RTL_FILES)

lint-verilator:
	@for k in 128 256; do \
	  echo "verilator --lint-only KEY_W=$$k"; \
	  $(VERILATOR) --lint-only -Wall -Wno-TIMESCALEMOD -Wno-DECLFILENAME \
	    --top-module aes_gcm_top -GKEY_W=$$k rtl/verilator_waiver.vlt -f rtl/filelist.f || exit 1; \
	done

# ---------------------------------------------------------------------------
# SystemVerilog benches (Verilator)
# ---------------------------------------------------------------------------
.PHONY: sim
sim: $(BUILD_DIR)/sim.f
	@if [ -z "$(TB)" ]; then echo "Usage: make sim TB=tb_aes_gcm_top"; exit 1; fi
	$(VERILATOR) --binary --trace-fst --top-module $(TB) --sv $(VL_WARN) \
	  -Mdir $(BUILD_DIR)/$(TB) -f $(BUILD_DIR)/sim.f
	$(BUILD_DIR)/$(TB)/V$(TB)

.PHONY: sim-all
sim-all: $(BUILD_DIR)/sim.f
	@pass=0; fail=0; failed=""; \
	BAR="================================================================"; \
	for tb in $(SV_TBS); do \
	  printf "\n\033[0;36m%s\033[0m\n\033[1;36m  TB: $$tb\033[0m\n\033[0;36m%s\033[0m\n\n" "$$BAR" "$$BAR"; \
	  compile_log="$(BUILD_DIR)/$$tb.compile.log"; run_log="$(BUILD_DIR)/$$tb.log"; \
	  if $(VERILATOR) --binary --trace-fst --top-module "$$tb" --sv $(VL_WARN) \
	       -Mdir "$(BUILD_DIR)/$$tb" -f "$(BUILD_DIR)/sim.f" > "$$compile_log" 2>&1; then \
	    "$(BUILD_DIR)/$$tb/V$$tb" > "$$run_log" 2>&1; run_status=$$?; cat "$$run_log"; \
	  else run_status=125; : > "$$run_log"; fi; \
	  if [ $$run_status -eq 0 ] \
	     && ! grep -Eq '(^|[[:space:]])FAIL(ED)?([[:space:]:\[]|$$)|[1-9][0-9]*[[:space:]]+failed' "$$run_log"; then \
	    printf "\n\033[1;32m  [PASS] $$tb\033[0m\n"; pass=$$((pass+1)); \
	  else \
	    printf "\n\033[1;31m  [FAIL] $$tb\033[0m\n"; \
	    if [ $$run_status -eq 125 ]; then cat "$$compile_log"; fi; \
	    fail=$$((fail+1)); failed="$$failed $$tb"; \
	  fi; \
	done; \
	total=$$((pass+fail)); \
	printf "\n\033[0;36m%s\033[0m\n\033[1m  Results: \033[1;32m$$pass\033[0;1m/$$total passed\033[0m\n" "$$BAR"; \
	if [ $$fail -gt 0 ]; then printf "\033[1;31m  Failed: $$failed\033[0m\n"; fi; \
	printf "\033[0;36m%s\033[0m\n\n" "$$BAR"; [ $$fail -eq 0 ]

.PHONY: wave
wave:
	@if [ -z "$(TB)" ]; then echo "Usage: make wave TB=tb_aes_gcm_top"; exit 1; fi
	$(SURFER) $(BUILD_DIR)/$(TB)/wave.fst &

# ---------------------------------------------------------------------------
# cocotb
# ---------------------------------------------------------------------------
COCOTB_VARS := SIM=$(SIM) KEY_W=$(KEY_W) PAGE_BYTES=$(PAGE_BYTES) WDT_TIMEOUT=$(WDT_TIMEOUT)

.PHONY: cocotb cocotb-kat cocotb-negative cocotb-random cocotb-geometry
cocotb:
	$(MAKE) -C tb/cocotb $(COCOTB_VARS) MODULE=$(MODULE)
cocotb-kat:
	$(MAKE) -C tb/cocotb $(COCOTB_VARS) MODULE=test_aes_gcm_kat
cocotb-negative:
	$(MAKE) -C tb/cocotb $(COCOTB_VARS) MODULE=test_aes_gcm_negative
cocotb-random:
	$(MAKE) -C tb/cocotb $(COCOTB_VARS) MODULE=test_aes_gcm_random
cocotb-geometry:
	$(MAKE) -C tb/cocotb $(COCOTB_VARS) MODULE=test_aes_gcm_geometry

# The documented regression matrix. Each line is KEY_W:PAGE_BYTES:MODULE.
MATRIX := \
  128:256:test_aes_gcm_kat   128:256:test_aes_gcm_negative 128:256:test_aes_gcm_random 128:256:test_aes_gcm_geometry \
  256:256:test_aes_gcm_kat   256:256:test_aes_gcm_negative 256:256:test_aes_gcm_random 256:256:test_aes_gcm_geometry \
  128:48:test_aes_gcm_kat    128:48:test_aes_gcm_geometry  128:48:test_aes_gcm_negative \
  256:48:test_aes_gcm_kat    256:48:test_aes_gcm_geometry \
  128:528:test_aes_gcm_kat   128:528:test_aes_gcm_geometry \
  256:528:test_aes_gcm_kat   256:528:test_aes_gcm_geometry \
  128:4096:test_aes_gcm_kat  128:4096:test_aes_gcm_geometry \
  256:4096:test_aes_gcm_kat  256:4096:test_aes_gcm_geometry 256:4096:test_aes_gcm_random

.PHONY: matrix
matrix:
	@pass=0; fail=0; failed=""; \
	for e in $(MATRIX); do \
	  k=$${e%%:*}; rest=$${e#*:}; p=$${rest%%:*}; m=$${rest#*:}; \
	  echo "=== matrix: KEY_W=$$k PAGE_BYTES=$$p MODULE=$$m SIM=$(SIM)"; \
	  if $(MAKE) -C tb/cocotb SIM=$(SIM) KEY_W=$$k PAGE_BYTES=$$p MODULE=$$m > $(BUILD_DIR)/matrix_$${k}_$${p}_$$m.log 2>&1 \
	     && grep -q "FAIL=0" $(BUILD_DIR)/matrix_$${k}_$${p}_$$m.log; then \
	    echo "    PASS"; pass=$$((pass+1)); \
	  else echo "    FAIL (see $(BUILD_DIR)/matrix_$${k}_$${p}_$$m.log)"; fail=$$((fail+1)); failed="$$failed $$e"; fi; \
	done; \
	echo "matrix: $$pass passed, $$fail failed $$failed"; [ $$fail -eq 0 ]

# ---------------------------------------------------------------------------
# Elaboration guard checks, conformance, vectors
# ---------------------------------------------------------------------------
.PHONY: elab-check
elab-check:
	$(PYTHON) tb/elab/run_elab_checks.py

.PHONY: conformance
conformance:
	$(PYTHON) tb/conformance/nist_ref_validation.py

.PHONY: vectors
vectors:
	$(PYTHON) scripts/gen_gcm_vectors.py

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) obj_dir sim_build tb/cocotb/sim_build tb/cocotb/results.xml
	rm -f *.vcd *.fst *.log
