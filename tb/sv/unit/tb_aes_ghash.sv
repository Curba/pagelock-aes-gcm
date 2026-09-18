// Purpose: Unit testbench for aes_ghash — NIST SP 800-38D TC1 and TC2 GHASH vectors
// Author: Claude
// Date: 2026-05-09

`timescale 1ns/1ps

module tb_aes_ghash;

  localparam int CLK_HALF = 5;  // 10 ns period

  // DUT ports
  logic         clk_i;
  logic         rst_ni;
  logic         init_i;
  logic [127:0] H_i;
  logic         valid_i;
  logic [127:0] data_i;
  logic         ready_o;
  logic [127:0] result_o;

  // DUT
  aes_ghash dut (
    .clk_i    (clk_i),
    .rst_ni   (rst_ni),
    .init_i   (init_i),
    .hash_i   (H_i),
    .valid_i  (valid_i),
    .data_i   (data_i),
    .ready_o  (ready_o),
    .result_o (result_o)
  );

  // Clock
  initial clk_i = 1'b0;
  always #CLK_HALF clk_i = ~clk_i;

  // Counters
  int pass_count;
  int fail_count;

  // -------------------------------------------------------------------------
  // Tasks
  // -------------------------------------------------------------------------

  task automatic reset_dut;
    rst_ni  = 1'b0;
    init_i  = 1'b0;
    valid_i = 1'b0;
    H_i     = '0;
    data_i  = '0;
    repeat (4) @(posedge clk_i);
    #1;
    rst_ni = 1'b1;
    @(posedge clk_i);
    #1;
  endtask

  // Load H and clear accumulator — waits for IDLE first so it is safe
  // to call even immediately after a block computation.
  task automatic ghash_init(input logic [127:0] H);
    while (!ready_o) @(posedge clk_i);
    #1;
    init_i = 1'b1;
    H_i    = H;
    @(posedge clk_i);
    #1;
    init_i = 1'b0;
  endtask

  // Feed one 128-bit block and wait for the 128-cycle GF multiply to finish.
  // Caller must ensure ready_o is high before calling (ghash_init guarantees this).
  task automatic ghash_block(input logic [127:0] blk);
    // ready_o is high on the same cycle valid_i fires (registered Moore output);
    // it drops low one cycle later when state_q transitions to ST_BUSY.
    valid_i = 1'b1;
    data_i  = blk;
    @(posedge clk_i);
    #1;
    valid_i = 1'b0;
    while (!ready_o) @(posedge clk_i);
    #1;
  endtask

  task automatic check(input string name, input logic [127:0] expected);
    if (result_o === expected) begin
      $display("PASS [%s]  got=%h", name, result_o);
      pass_count++;
    end else begin
      $display("FAIL [%s]", name);
      $display("  expected = %h", expected);
      $display("  got      = %h", result_o);
      fail_count++;
    end
  endtask

  // -------------------------------------------------------------------------
  // NIST test vectors
  //
  // H = AES(K=0^128, 0^128) = 66e94bd4ef8a2c3b884cfa59ca342b2e
  //
  // TC1: K=0^128, IV=0^96, P=empty, A=empty
  //   GHASH input  : len_block = {len(A)=0, len(C)=0} = 0^128
  //   GHASH result : 0^128  (because 0^128 * H = 0 in GF(2^128))
  //   Tag          : EJ0 XOR GHASH = 58e2fccefa7e3061367f1d57a4e7455a
  //
  // TC2: K=0^128, IV=0^96, P=0^128 (1 block), A=empty
  //   CT           : 0388dace60b6a392f328c2b971b2fe78
  //   GHASH inputs : CT_block, len_block={0, 128 bits}=0x80
  //   GHASH result : Tag XOR EJ0
  //                = ab6e47d42cec13bdf53a67b21257bddf
  //                  XOR 58e2fccefa7e3061367f1d57a4e7455a
  //                = f38cbb1ad69223dcc3457ae5b6b0f885
  // -------------------------------------------------------------------------

  localparam logic [127:0] H_TC         = 128'h66e94bd4ef8a2c3b884cfa59ca342b2e;

  localparam logic [127:0] TC1_LEN_BLK  = 128'h0;
  localparam logic [127:0] TC1_EXPECTED = 128'h0;

  localparam logic [127:0] TC2_CT_BLK   = 128'h0388dace60b6a392f328c2b971b2fe78;
  localparam logic [127:0] TC2_LEN_BLK  = 128'h00000000000000000000000000000080;
  localparam logic [127:0] TC2_EXPECTED = 128'hf38cbb1ad69223dcc3457ae5b6b0f885;

  // -------------------------------------------------------------------------
  // Stimulus
  // -------------------------------------------------------------------------

  initial begin
    pass_count = 0;
    fail_count = 0;

    $display("=== tb_aes_ghash: NIST SP 800-38D TC1/TC2 ===");

    reset_dut();

    // ------------------------------------------------------------------
    // TC1: GHASH_H([0^128])
    // Zero input * H = 0 in GF(2^128); verifies accumulator reset and
    // that the multiplier correctly produces 0 for a zero operand.
    // ------------------------------------------------------------------
    $display("--- TC1: single zero block (len block for empty plaintext/AAD) ---");
    ghash_init(H_TC);
    ghash_block(TC1_LEN_BLK);
    check("TC1 GHASH", TC1_EXPECTED);

    // ------------------------------------------------------------------
    // TC2: GHASH_H([CT_block, len_block])
    // Two-block sequence — exercises accumulator carry-over between blocks
    // and the full GF multiply for a non-trivial operand.
    // ------------------------------------------------------------------
    $display("--- TC2: CT block then len block ---");
    ghash_init(H_TC);
    ghash_block(TC2_CT_BLK);
    ghash_block(TC2_LEN_BLK);
    check("TC2 GHASH", TC2_EXPECTED);

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------
    $display("=== %0d passed, %0d failed ===", pass_count, fail_count);
    if (fail_count == 0)
      $display("ALL TESTS PASSED");
    else
      $display("TESTS FAILED");

    $finish;
  end

  // Watchdog: two blocks at 128 cycles each plus generous overhead
  initial begin
    #50000;
    $display("TIMEOUT — simulation did not finish");
    $finish;
  end

endmodule
