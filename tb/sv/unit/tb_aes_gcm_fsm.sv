// Purpose: Unit testbench for aes_gcm_fsm — KEY_INIT → FINALIZE (behavioral AES stub)
// Author: Claude
// Date: 2026-05-25
//
// AES core behavioral stub faithfully models secworks handshake:
//   - ready drops ONE CYCLE after init/next is accepted (registered)
//   - ready returns after LATENCY cycles
//   - result_valid goes HIGH when a `next` completes and STAYS HIGH (level-held)
//     until a new init/next is issued — this is NOT a pulse
//   - result is a deterministic lookup on the latched block
//
// GHASH is stubbed as always-ready (ghash_ready_i=1).
//
// Intermediate one-cycle pulses (key_consumed_o, ghash_init_o, etc.) are caught
// with @(posedge signal) monitors launched before the DUT starts.
//
// Expected tag: ghash_result_i held at 0, reg_EJ0_q should be EJ0_MOCK
//   → tag_o = 0 ^ EJ0_MOCK = EJ0_MOCK
//
// KNOWN FSM BUG (revealed by level-held result_valid):
//   At the first cycle of ST_ENC_J0, the stale result_valid from GEN_H is still
//   HIGH.  The FSM simultaneously fires aes_next_o (for J0) AND sees aes_valid_i=1
//   (stale H result). The `if (aes_valid_i)` sequential branch in ST_ENC_J0 wins,
//   latching reg_EJ0_q = H_MOCK instead of EJ0_MOCK, and immediately advancing to
//   ST_PROC_AAD before AES(K,J0) is captured.  This causes tag_o = H_MOCK.

`timescale 1ns/1ps

// ============================================================================
// Behavioral AES stub — faithfully models secworks aes_core handshake
// ============================================================================
module aes_core_stub #(parameter int LATENCY = 4) (
  input  logic         clk_i,
  input  logic         rst_ni,
  input  logic         init_i,
  input  logic         next_i,
  input  logic [127:0] block_i,
  output logic         ready_o,
  output logic         result_valid_o,
  output logic [127:0] result_o
);

  localparam logic [127:0] H_MOCK   = 128'haaaabbbbccccdddd0000111122223333;
  localparam logic [127:0] EJ0_MOCK = 128'hdeadbeefcafebabe0123456789abcdef;
  localparam logic  [95:0] IV_STUB  = 96'hcafebabe_facedbad_decaf888;

  function automatic logic [127:0] lookup(input logic [127:0] blk);
    if (blk == 128'h0)
      return H_MOCK;
    else if (blk == {IV_STUB, 32'h0000_0001})
      return EJ0_MOCK;
    else
      return blk ^ 128'hc0dec0dec0dec0dec0dec0dec0dec0de;
  endfunction

  logic [4:0]   cnt_q;
  logic         busy_q;
  logic         is_next_q;
  logic [127:0] latch_block_q;
  logic         result_valid_q;
  logic [127:0] result_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      cnt_q          <= '0;
      busy_q         <= 1'b0;
      is_next_q      <= 1'b0;
      latch_block_q  <= '0;
      result_valid_q <= 1'b0;
      result_q       <= '0;
    end else if (!busy_q && (init_i || next_i)) begin
      busy_q         <= 1'b1;
      is_next_q      <= next_i && !init_i;
      latch_block_q  <= block_i;
      cnt_q          <= 5'(LATENCY - 1);
      result_valid_q <= 1'b0;   // clear previous result on new op
    end else if (busy_q) begin
      if (cnt_q == '0) begin
        busy_q <= 1'b0;
        if (is_next_q) begin
          result_valid_q <= 1'b1;
          result_q       <= lookup(latch_block_q);
        end
      end else begin
        cnt_q <= cnt_q - 5'd1;
      end
    end
    // result_valid_q stays HIGH until the next init/next (cleared above)
  end

  assign ready_o        = !busy_q;
  assign result_valid_o = result_valid_q;
  assign result_o       = result_q;

endmodule : aes_core_stub


// ============================================================================
// Testbench
// ============================================================================
module tb_aes_gcm_fsm;

  // Default geometry of aes_gcm_top (AES-128, 256-byte page)
  localparam int KEY_W  = 128;
  localparam int IV_W   = 96;
  localparam int TAG_W  = 128;
  localparam int DATA_W = 128;
  localparam int AAD_W  = 128;
  import aes_gcm_pkg::*;

  localparam int CLK_HALF = 5;

  // -------------------------------------------------------------------------
  // DUT ports
  // -------------------------------------------------------------------------
  logic         clk_i, rst_ni;
  logic         start_i, encdec_i;
  logic [127:0] key_i, aad_i, exp_tag_i;
  logic  [95:0] iv_i;
  logic         aad_valid_i;
  logic         aad_ready_o;
  logic         data_valid_i;
  logic         data_ready_o;
  logic         done_o;
  logic [127:0] tag_o;
  logic         tag_match_o;
  logic [127:0] key_o;
  logic         aes_init_o, aes_next_o;
  logic [127:0] aes_block_o;
  logic         ghash_init_o, ghash_valid_o, ghash_sel_ct_o;
  logic [127:0] ghash_H_o, fsm_ghash_data_o;
  logic [127:0] ghash_result_i;
  logic         ghash_ready_i;
  logic         block_out_valid_o, last_block_o;
  logic         key_consumed_o;
  logic         fsm_err_o;

  logic         aes_ready_w, aes_valid_w;
  logic [127:0] aes_result_w;

  // -------------------------------------------------------------------------
  // Stub + DUT
  // -------------------------------------------------------------------------
  aes_core_stub #(.LATENCY(4)) u_stub (
    .clk_i         (clk_i),
    .rst_ni        (rst_ni),
    .init_i        (aes_init_o),
    .next_i        (aes_next_o),
    .block_i       (aes_block_o),
    .ready_o       (aes_ready_w),
    .result_valid_o(aes_valid_w),
    .result_o      (aes_result_w)
  );

  aes_gcm_fsm dut (
    .clk_i              (clk_i),
    .rst_ni             (rst_ni),
    .start_i            (start_i),
    .encdec_i           (encdec_i),
    .key_i              (key_i),
    .iv_i               (iv_i),
    .aad_i              (aad_i),
    .aad_valid_i        (aad_valid_i),
    .aad_ready_o        (aad_ready_o),
    .exp_tag_i          (exp_tag_i),
    .data_valid_i       (data_valid_i),
    .data_ready_o       (data_ready_o),
    .done_o             (done_o),
    .tag_o              (tag_o),
    .tag_match_o        (tag_match_o),
    .aes_key_o          (key_o),
    .aes_init_o         (aes_init_o),
    .aes_next_o         (aes_next_o),
    .aes_block_o        (aes_block_o),
    .aes_ready_i        (aes_ready_w),
    .aes_valid_i        (aes_valid_w),
    .aes_result_i       (aes_result_w),
    .ghash_init_o       (ghash_init_o),
    .ghash_valid_o      (ghash_valid_o),
    .ghash_sel_ct_o     (ghash_sel_ct_o),
    .ghash_hash_o       (ghash_H_o),
    .ghash_fsm_data_o   (fsm_ghash_data_o),
    .ghash_ready_i      (ghash_ready_i),
    .ghash_result_i     (ghash_result_i),
    .data_out_ready_i   (1'b1),
    .block_out_valid_o  (block_out_valid_o),
    .last_block_o       (last_block_o),
    .key_consumed_o     (key_consumed_o),
    .fsm_err_o          (fsm_err_o),
    .busy_o             ()
  );

  initial clk_i = 1'b0;
  always #CLK_HALF clk_i = ~clk_i;

  int pass_count, fail_count;

  // -------------------------------------------------------------------------
  // Test constants
  // -------------------------------------------------------------------------
  localparam logic [127:0] KEY_IN   = 128'h2b7e151628aed2a6abf7158809cf4f3c;
  localparam logic  [95:0] IV_IN    = 96'hcafebabe_facedbad_decaf888;
  localparam logic [127:0] AAD_IN   = 128'h00000000_00000000_00000000_00c0ffee;
  localparam logic [127:0] H_MOCK   = 128'haaaabbbbccccdddd0000111122223333;
  localparam logic [127:0] EJ0_MOCK = 128'hdeadbeefcafebabe0123456789abcdef;
  // If EJ0 is correctly captured: tag = 0 ^ EJ0_MOCK
  localparam logic [127:0] EXP_TAG  = EJ0_MOCK;

  // -------------------------------------------------------------------------
  // Event flags — set by fork-join_none monitors before DUT starts
  // -------------------------------------------------------------------------
  logic caught_key_consumed;
  logic caught_ghash_init;
  logic caught_aad_valid;
  logic caught_last_block;
  logic [127:0] block_at_gen_h;    // aes_block_o when aes_next_o fires in GEN_H
  logic [127:0] block_at_enc_j0;   // aes_block_o when aes_next_o fires in ENC_J0
  logic [127:0] H_at_prep_j0;      // ghash_H_o when ghash_init_o fires
  logic [127:0] aad_at_strobe;     // fsm_ghash_data_o when ghash_valid fires (AAD)
  int           aes_next_count;    // how many times aes_next_o fires total
  int           block_out_count;

  // -------------------------------------------------------------------------
  // Tasks
  // -------------------------------------------------------------------------
  task automatic reset_dut;
    rst_ni         = 1'b0;
    start_i        = 1'b0;
    encdec_i       = 1'b1;
    key_i          = '0;
    iv_i           = '0;
    aad_i          = '0;
    exp_tag_i      = '0;
    data_valid_i   = 1'b0;
    aad_valid_i    = 1'b0;
    ghash_ready_i  = 1'b1;
    ghash_result_i = '0;
    // Reset event flags
    caught_key_consumed = 1'b0;
    caught_ghash_init   = 1'b0;
    caught_aad_valid    = 1'b0;
    caught_last_block   = 1'b0;
    block_at_gen_h      = '0;
    block_at_enc_j0     = '0;
    H_at_prep_j0        = '0;
    aad_at_strobe       = '0;
    aes_next_count      = 0;
    block_out_count     = 0;
    repeat (4) @(posedge clk_i);
    #1;
    rst_ni = 1'b1;
    @(posedge clk_i);
    #1;
  endtask

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
      $display("  PASS  %s  = %h", name, got);
      pass_count++;
    end else begin
      $display("  FAIL  %s", name);
      $display("          expected = %h", exp);
      $display("          got      = %h", got);
      fail_count++;
    end
  endtask

  task automatic chk_int(input string name, input int got, input int exp);
    if (got == exp) begin
      $display("  PASS  %s = %0d", name, got);
      pass_count++;
    end else begin
      $display("  FAIL  %s: expected %0d, got %0d", name, exp, got);
      fail_count++;
    end
  endtask

  // -------------------------------------------------------------------------
  // Parallel monitors — launched before DUT kicks off, run until done_o
  // -------------------------------------------------------------------------
  task automatic launch_monitors;
    // key_consumed_o: one-cycle pulse at end of ST_KEY_INIT
    fork
      begin
        @(posedge key_consumed_o);
        caught_key_consumed = 1'b1;
      end
    join_none

    // aes_next_o: first assertion → GEN_H (zero block), second → ENC_J0 (J0 block)
    fork
      begin : aes_next_monitor
        forever begin
          @(posedge aes_next_o);
          aes_next_count++;
          if (aes_next_count == 1)
            block_at_gen_h  = aes_block_o;
          else if (aes_next_count == 2)
            block_at_enc_j0 = aes_block_o;
        end
      end : aes_next_monitor
    join_none

    // ghash_init_o: one-cycle pulse in ST_PREP_J0
    fork
      begin
        @(posedge ghash_init_o);
        caught_ghash_init = 1'b1;
        H_at_prep_j0      = ghash_H_o;
      end
    join_none

    // ghash_valid_o: first assertion → AAD block in ST_PROC_AAD
    fork
      begin
        @(posedge ghash_valid_o);
        caught_aad_valid  = 1'b1;
        aad_at_strobe     = fsm_ghash_data_o;
      end
    join_none

    // block_out_valid_o: count and catch last_block_o
    fork
      begin : blk_monitor
        forever begin
          @(posedge block_out_valid_o);
          block_out_count++;
          if (last_block_o) caught_last_block = 1'b1;
        end
      end : blk_monitor
    join_none
  endtask

  // -------------------------------------------------------------------------
  // Stimulus
  // -------------------------------------------------------------------------
  initial begin
    pass_count = 0;
    fail_count = 0;
    $display("=== tb_aes_gcm_fsm: KEY_INIT → FINALIZE (behavioral AES stub) ===");

    reset_dut();

    chk_bit("fsm_err_o LOW at reset", fsm_err_o, 1'b0);
    chk_bit("done_o LOW at reset",    done_o,     1'b0);

    // Launch all monitors before kicking off the DUT
    launch_monitors();

    // -----------------------------------------------------------------------
    // Start the DUT
    // -----------------------------------------------------------------------
    @(posedge clk_i); #1;
    start_i     = 1'b1;
    key_i       = KEY_IN;
    iv_i        = IV_IN;
    aad_i       = AAD_IN;
    encdec_i    = 1'b1;
    aad_valid_i = 1'b1;   // assert with start; hold until FSM signals consume-ready
    // Deassert one cycle after the FSM pulses aad_ready_o (consume cycle)
    fork
      begin
        @(posedge aad_ready_o);
        @(posedge clk_i); #1;
        aad_valid_i = 1'b0;
      end
    join_none
    @(posedge clk_i); #1;
    start_i = 1'b0;

    // Verify combinational outputs immediately after FSM enters ST_KEY_INIT
    $display("--- ST_KEY_INIT check (combinational at entry) ---");
    chk_bit("aes_init_o = 1  (key_init_sent_q=0)", aes_init_o, 1'b1);
    chk_bit("aes_next_o = 0  (not in GEN_H yet)",  aes_next_o, 1'b0);
    chk_vec("key_o latched from key_i",             key_o,      KEY_IN);

    // -----------------------------------------------------------------------
    // Drive data_valid_i high for ST_PROC_PAYLOAD — FSM will handshake when ready
    // -----------------------------------------------------------------------
    data_valid_i = 1'b1;

    // -----------------------------------------------------------------------
    // Wait for FINALIZE to complete
    // -----------------------------------------------------------------------
    begin : wait_done
      automatic int timeout = 0;
      while (!done_o) begin
        @(posedge clk_i);
        timeout++;
        if (timeout > 2000) begin
          $display("  FAIL  TIMEOUT waiting for done_o (2000 cycles)");
          fail_count++;
          break;
        end
      end
      #1;
    end : wait_done

    data_valid_i = 1'b0;
    // Let monitors catch final events
    @(posedge clk_i); #1;
    @(posedge clk_i); #1;

    // -----------------------------------------------------------------------
    // Check results accumulated by monitors
    // -----------------------------------------------------------------------
    $display("--- ST_KEY_INIT ---");
    chk_bit("key_consumed_o pulsed (caught by monitor)", caught_key_consumed, 1'b1);

    $display("--- ST_GEN_H ---");
    chk_bit("aes_next_o fired at least once (GEN_H)",   aes_next_count > 0, 1'b1);
    chk_vec("block at GEN_H aes_next = 0^128",          block_at_gen_h,     128'h0);

    $display("--- ST_PREP_J0 ---");
    chk_bit("ghash_init_o pulsed (caught by monitor)",  caught_ghash_init, 1'b1);
    chk_vec("ghash_H_o = H_MOCK at ghash_init",         H_at_prep_j0,      H_MOCK);

    $display("--- ST_ENC_J0 ---");
    // With a correctly working FSM, aes_next_o fires a SECOND time for J0.
    // The level-held result_valid bug causes the FSM to skip the second fire
    // (it exits immediately via the stale aes_valid_i=1), so aes_next_count==1.
    chk_bit("aes_next_o fired >=2 times (GEN_H + ENC_J0)",
            aes_next_count >= 2, 1'b1);
    chk_vec("block at ENC_J0 aes_next = {IV,0x00000001}",
            block_at_enc_j0, {IV_IN, 32'h0000_0001});

    $display("--- ST_PROC_AAD ---");
    chk_bit("ghash_valid_o pulsed for AAD (monitor)",   caught_aad_valid, 1'b1);
    chk_vec("AAD data = AAD_IN",                        aad_at_strobe,    AAD_IN);

    $display("--- ST_PROC_PAYLOAD ---");
    chk_int("14 blocks processed (block_out_count)",    block_out_count, 14);
    chk_bit("last_block_o fired on block 14",           caught_last_block, 1'b1);

    $display("--- ST_FINALIZE ---");
    chk_bit("done_o = 1",                               done_o,     1'b1);
    chk_bit("fsm_err_o = 0",                            fsm_err_o,  1'b0);
    // tag_o = ghash_result_i(0) ^ reg_EJ0_q.
    // If EJ0 bug is NOT present: tag = 0 ^ EJ0_MOCK = EJ0_MOCK.
    // If EJ0 bug IS present:     tag = 0 ^ H_MOCK   = H_MOCK.
    chk_vec("tag_o == EXP_TAG (EJ0_MOCK) — fails if EJ0-latch bug present",
            tag_o, EXP_TAG);
    chk_bit("tag_match_o = 0 (encrypt mode)", tag_match_o, 1'b0);

    $display("=== %0d passed, %0d failed ===", pass_count, fail_count);
    if (fail_count == 0)
      $display("ALL TESTS PASSED");
    else
      $display("TESTS FAILED");

    $finish;
  end

  initial begin
    #200_000;
    $display("TIMEOUT — simulation did not finish");
    $finish;
  end

endmodule
