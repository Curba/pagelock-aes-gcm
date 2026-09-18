// Purpose: Deep-backpressure regression — Finding 1 / Issue #25 fix.
// Author: Baris
// Date: 2026-06-05
//
// What this tests:
//   block_out_valid_o = pl_aes_sent_q && !pl_ghash_sent_q
//                       && aes_valid_i && ghash_ready_i   (FSM phase 2, fixed)
//   ghash_valid_o     = block_out_valid_o && data_out_ready_i
//
//   block_out_valid_o is independent of data_out_ready_i after the fix
//   (AMBA rule: valid must not depend on ready). The output strobe is held
//   HIGH while AES result is available, and drops after the downstream accepts.
//   GHASH is fed atomically with the downstream acceptance.
//
//   Secworks aes_core.v: result_valid goes HIGH in the CTRL_NEXT→CTRL_IDLE
//   transition and stays HIGH until the next init or next command. aes_valid_i
//   therefore stays HIGH during extended backpressure, keeping block_out_valid_o
//   asserted until the FIFO accepts.
//
// Scenario:
//   Deassert cipher_data_out_ready_i at #1 AFTER block STALL_BLK's handshake.
//   Hold for DEEP_STALL cycles (well past AES latency ~11 cycles). Reassert
//   ready. block_out_valid_o stays HIGH throughout; GHASH and downstream both
//   see the transfer on the cycle ready returns.
//
// Expected result: PASS — all 16 blocks correct, no error.
//
// Structure: fully sequential (no fork/join) — one block fed and captured at
// a time. Avoids Verilator fork shared-variable races and matches the FSM's
// non-pipelined block cadence (input N+1 not accepted until block N's GHASH
// phase completes).
`timescale 1ns/1ps

module tb_aes_gcm_deep_backpressure;

  localparam int CLK_HALF     = 5;     // 10 ns period → 100 MHz
  localparam int NBLOCKS      = 14;
  localparam int DEEP_STALL   = 80;    // >> AES block latency (~11 cycles)
  localparam int STALL_BLK    = 4;     // apply stall after this block's handshake
  localparam int BLOCK_TIMEOUT = 300;  // per-block wait limit (cycles) before deadlock declared

  // -------------------------------------------------------------------------
  // DUT ports
  // -------------------------------------------------------------------------
  logic         clk_i, rst_ni;
  logic         cipher_start_i, cipher_mode_i;
  logic [127:0] cipher_key_i, cipher_aad_i, cipher_exp_tag_i;
  logic  [95:0] cipher_iv_i;
  logic [127:0] cipher_plaintext_data_i, cipher_spi_data_i;
  logic         cipher_aad_valid_i,      cipher_aad_ready_o;
  logic         cipher_data_in_valid_i,  cipher_data_in_ready_o;
  logic [127:0] cipher_data_out_o;
  logic         cipher_data_out_valid_o;
  logic         cipher_data_out_ready_i;
  logic         cipher_data_out_last_o;
  logic         cipher_page_done_o;
  logic [4:0]   cipher_total_blocks_o;
  logic         cipher_done_o;
  logic         cipher_tag_ok_o;
  logic         cipher_busy_o, cipher_err_o;
  logic         key_consumed_nc, key_ready_nc;
  logic [3:0]   state_nc;

  // -------------------------------------------------------------------------
  // DUT
  // -------------------------------------------------------------------------
  aes_gcm_top dut (
    .clk_i                    (clk_i),
    .rst_ni                   (rst_ni),
    .cmd_valid_i             (cipher_start_i),
    .cmd_ready_o             (cipher_aad_ready_o),
    .cmd_mode_i              (cipher_mode_i),
    .cmd_key_i               (cipher_key_i),
    .cmd_iv_i                (cipher_iv_i),
    .cmd_aad_i               (cipher_aad_i),
    .cmd_exp_tag_i           (cipher_exp_tag_i),
    .data_in_valid_i         (cipher_data_in_valid_i),
    .data_in_ready_o         (cipher_data_in_ready_o),
    .data_in_i               (cipher_mode_i ? cipher_plaintext_data_i : cipher_spi_data_i),
    .data_out_o              (cipher_data_out_o),
    .data_out_valid_o        (cipher_data_out_valid_o),
    .data_out_ready_i        (cipher_data_out_ready_i),
    .rsp_valid_o             (cipher_done_o),
    .rsp_ready_i             (1'b1),
    .rsp_auth_ok_o           (cipher_tag_ok_o),
    .rsp_error_o             (cipher_err_o),
    .data_out_last_o         (cipher_data_out_last_o)
  );

  assign key_consumed_nc       = cipher_start_i && cipher_aad_ready_o;
  assign key_ready_nc          = cipher_aad_ready_o;
  assign cipher_busy_o         = !cipher_aad_ready_o;
  assign cipher_page_done_o    = cipher_done_o;
  assign cipher_total_blocks_o = cipher_mode_i ? 5'd16 : 5'd14;
  assign state_nc              = '0;

  // -------------------------------------------------------------------------
  // Clock
  // -------------------------------------------------------------------------
  initial clk_i = 1'b0;
  always #CLK_HALF clk_i = ~clk_i;

  // TB watchdog — long enough for two full runs plus the 4095-cycle HW watchdog
  initial begin
    #12_000_000;
    $display("TIMEOUT — simulation did not finish");
    $finish;
  end

  // Sticky error monitor — reset by rst_ni pulse in reset_dut
  logic err_seen;
  always @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) err_seen <= 1'b0;
    else if (cipher_err_o) err_seen <= 1'b1;
  end

  // -------------------------------------------------------------------------
  // Test constants
  // -------------------------------------------------------------------------
  localparam logic [127:0] KEY = 128'h000102030405060708090a0b0c0d0e0f;
  localparam logic  [95:0] IV  = 96'hdeadbeef_cafebabe_01234567;
  localparam logic [127:0] AAD = 128'h00000000_00000000_00000000_00abcdef;

  // -------------------------------------------------------------------------
  // Assertion helpers
  // -------------------------------------------------------------------------
  int pass_count = 0;
  int fail_count = 0;

  task automatic chk_bit(input string name, input logic got, input logic exp);
    if (got === exp) begin
      $display("  PASS  %s", name);
      pass_count++;
    end else begin
      $display("  FAIL  %s  (expected %b, got %b)", name, exp, got);
      fail_count++;
    end
  endtask

  task automatic chk_vec(input string name, input logic [127:0] got,
                          input logic [127:0] exp);
    if (got === exp) begin
      $display("  PASS  %s", name);
      pass_count++;
    end else begin
      $display("  FAIL  %s", name);
      $display("          expected = %h", exp);
      $display("          got      = %h", got);
      fail_count++;
    end
  endtask

  // -------------------------------------------------------------------------
  // Reset
  // -------------------------------------------------------------------------
  task automatic reset_dut;
    rst_ni                  = 1'b0;
    cipher_start_i          = 1'b0;
    cipher_mode_i           = 1'b1;
    cipher_key_i            = '0;
    cipher_iv_i             = '0;
    cipher_aad_i            = '0;
    cipher_exp_tag_i        = '0;
    cipher_aad_valid_i      = 1'b0;
    cipher_data_in_valid_i  = 1'b0;
    cipher_data_out_ready_i = 1'b1;
    cipher_plaintext_data_i = '0;
    cipher_spi_data_i       = '0;
    repeat (4) @(posedge clk_i); #1;
    rst_ni = 1'b1;
    @(posedge clk_i); #1;
  endtask

  // -------------------------------------------------------------------------
  // Start encrypt (AAD handshake in background fork)
  // -------------------------------------------------------------------------
  task automatic start_encrypt;
    @(posedge clk_i); #1;
    cipher_start_i     = 1'b1;
    cipher_mode_i      = 1'b1;
    cipher_key_i       = KEY;
    cipher_iv_i        = IV;
    cipher_aad_i       = AAD;
    cipher_exp_tag_i   = '0;
    cipher_aad_valid_i = 1'b1;
    fork
      begin
        @(posedge cipher_aad_ready_o);
        @(posedge clk_i); #1;
        cipher_aad_valid_i = 1'b0;
      end
    join_none
    @(posedge clk_i iff cipher_aad_ready_o); #1;
    cipher_start_i = 1'b0;
  endtask

  // -------------------------------------------------------------------------
  // Wait for a single valid output block with per-block timeout.
  // Sets deadlock_out = 1 and returns early if no block appears.
  // -------------------------------------------------------------------------
  task automatic wait_output_block(output logic [127:0] data, output logic deadlock_out);
    int tc;
    tc           = 0;
    deadlock_out = 1'b0;
    data         = '0;
    while (!(cipher_data_out_valid_o && cipher_data_out_ready_i)) begin
      @(posedge clk_i); #1;
      tc++;
      if (tc > BLOCK_TIMEOUT || err_seen) begin
        deadlock_out = 1'b1;
        return;
      end
    end
    data = cipher_data_out_o;
  endtask

  // =========================================================================
  // run_encrypt
  //   Fully sequential encrypt. stall_blk = -1 → no stall (reference run).
  //   On block stall_blk: deassert ready at #1 AFTER the handshake posedge,
  //   hold for stall_cycles, reassert. This places reg_ready_q = 0 from
  //   cycle 1 of AES computation onward, covering the aes_valid_i window.
  // =========================================================================
  task automatic run_encrypt(
    input  int           stall_blk,
    input  int           stall_cycles,
    output logic [127:0] ct_out     [NBLOCKS],
    output logic [127:0] out_tag,
    output int           blocks_captured,
    output logic         deadlocked
  );
    logic [127:0] dummy;
    logic         dl;
    blocks_captured = 0;
    deadlocked      = 1'b0;
    out_tag         = '0;

    start_encrypt();

    // Wait for FSM to finish setup (ST_KEY_INIT → ... → ST_PROC_PAYLOAD)
    while (!cipher_data_in_ready_o) @(posedge clk_i);
    #1;

    // Feed and capture each payload block sequentially.
    // The FSM is non-pipelined: block N's input is not accepted until block
    // N-1's GHASH phase completes, so waiting for output before next input
    // is both safe and correct.
    for (int i = 0; i < NBLOCKS && !deadlocked; i++) begin

      // Wait for FSM payload-ready (may need to wait after previous GHASH)
      while (!cipher_data_in_ready_o) @(posedge clk_i);
      #1;

      // Present block
      cipher_plaintext_data_i = P[i];
      cipher_data_in_valid_i  = 1'b1;
      @(posedge clk_i); #1;
      // Handshake occurred on this posedge. aes_next_o fired.
      cipher_data_in_valid_i = 1'b0;

      if (i == stall_blk) begin
        // Deassert ready NOW — reg_ready_q latches 0 on the very next posedge,
        // which is cycle 1 of the AES computation. It stays 0 through
        // aes_valid_i (fired ~11 cycles later), causing the deadlock.
        cipher_data_out_ready_i = 1'b0;
        repeat (stall_cycles) @(posedge clk_i);
        #1;
        cipher_data_out_ready_i = 1'b1;
      end

      // Collect block i output
      wait_output_block(ct_out[i], dl);
      if (dl) begin
        deadlocked = 1'b1;
        $display("  NOTE  No output for block %0d after %0d cycles (err_seen=%b)",
                 i, BLOCK_TIMEOUT, err_seen);
      end else begin
        blocks_captured++;
      end
    end

    if (!deadlocked) begin
      // OC_TAG block (encrypt appends tag) — capture from stream
      wait_output_block(out_tag, dl);
      if (dl) deadlocked = 1'b1;
      else    blocks_captured++;

      // OC_AAD block (encrypt appends latched AAD)
      if (!deadlocked) begin
        wait_output_block(dummy, dl);
        if (dl) deadlocked = 1'b1;
        else    blocks_captured++;
      end
    end

    if (!deadlocked) begin
      while (!cipher_done_o) @(posedge clk_i);
      #1;
    end
  endtask

  // =========================================================================
  // Plaintext — block i = all-bytes (i+1), consistent with other TBs
  // =========================================================================
  logic [127:0] P [NBLOCKS];

  // =========================================================================
  // Stimulus
  // =========================================================================
  logic [127:0] ref_ct  [NBLOCKS];
  logic [127:0] ref_tag;
  logic [127:0] stall_ct [NBLOCKS];
  logic [127:0] stall_tag;
  int           blocks_captured;
  logic         deadlocked;

  initial begin
    pass_count = 0;
    fail_count = 0;
    $display("=== tb_aes_gcm_deep_backpressure: Finding-1 deadlock regression ===");
    $display("    STALL_BLK=%0d  DEEP_STALL=%0d cycles  BLOCK_TIMEOUT=%0d",
             STALL_BLK, DEEP_STALL, BLOCK_TIMEOUT);

    for (int i = 0; i < NBLOCKS; i++)
      P[i] = {16{8'(i + 1)}};

    // -------------------------------------------------------------------
    // Reference run — no stall; establishes expected CT values and tag
    // -------------------------------------------------------------------
    $display("\n--- Reference run (ready=1 throughout) ---");
    reset_dut();
    run_encrypt(-1, 0, ref_ct, ref_tag, blocks_captured, deadlocked);

    chk_bit("Reference: no deadlock",       !deadlocked,           1'b1);
    chk_bit("Reference: 16 blocks captured", logic'(blocks_captured == 16), 1'b1);
    chk_bit("Reference: ref_tag non-zero",  (ref_tag !== '0),      1'b1);
    chk_bit("Reference: cipher_err_o = 0",  cipher_err_o,          1'b0);
    $display("  ref_tag = %h", ref_tag);

    // -------------------------------------------------------------------
    // Deep-stall run
    // -------------------------------------------------------------------
    $display("\n--- Deep-stall run: ready deasserted after block %0d handshake ---",
             STALL_BLK);
    $display("    reg_ready_q = 0 from cycle 1 of AES computation,");
    $display("    held for %0d cycles (aes_valid_i fires at ~11 cycles)", DEEP_STALL);
    reset_dut();
    run_encrypt(STALL_BLK, DEEP_STALL, stall_ct, stall_tag,
                blocks_captured, deadlocked);

    if (deadlocked)
      $display("  NOTE  Deadlock confirmed: FSM stuck or watchdog tripped");

    // cipher_err_o must not assert — a trip means the watchdog rescued a deadlock
    chk_bit("cipher_err_o did not assert (no watchdog trip)", err_seen,    1'b0);

    // All 16 output blocks must have been captured
    chk_bit("All 16 output blocks captured",
            logic'(blocks_captured == 16), 1'b1);

    if (!deadlocked && !err_seen) begin
      // Ciphertext must be identical to the reference (stall must not corrupt)
      for (int i = 0; i < NBLOCKS; i++)
        chk_vec($sformatf("CT[%02d] matches reference", i), stall_ct[i], ref_ct[i]);

      chk_vec("Tag matches reference", stall_tag, ref_tag);
      chk_bit("cipher_err_o = 0 at end", cipher_err_o, 1'b0);
    end else begin
      $display("  NOTE  Skipping CT/tag checks — deadlock or error present");
      fail_count++;
    end

    // -------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------
    $display("");
    $display("=== %0d passed, %0d failed ===", pass_count, fail_count);
    if (fail_count == 0) begin
      $display("ALL TESTS PASSED");
    end else begin
      $display("TESTS FAILED");
      $fatal(1, "Deep-backpressure regression failed");
    end

    $finish;
  end

endmodule
