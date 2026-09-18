// AES-128-GCM tb_aes_smoke, initial test Author: Baris. Date: 2026-05-04.
// tb/cipher/sv/integration/tb_aes_smoke.sv
`timescale 1ns/1ps

module tb_aes_smoke;

  // ------------------------------------------------------------------------
  // Signals & Clock/Reset
  // ------------------------------------------------------------------------
  logic clk_i   = 1'b0;
  logic rst_ni  = 1'b0;

  always #5 clk_i = ~clk_i; // 100MHz clock

  // ------------------------------------------------------------------------
  // DUT Interface
  // ------------------------------------------------------------------------
  logic           encdec_i;
  logic           init_i;
  logic           next_i;
  logic           ready_o;
  logic [255:0]   key_i;
  logic           keylen_i;
  logic [127:0]   block_i;
  logic [127:0]   result_o;
  logic           result_valid_o;

  // ------------------------------------------------------------------------
  // DUT Instantiation (secworks aes_core)
  // ------------------------------------------------------------------------
  aes_core dut (
    .clk          (clk_i),
    .reset_n      (rst_ni),
    .encdec       (encdec_i),
    .init         (init_i),
    .next         (next_i),
    .ready        (ready_o),
    .key          (key_i),
    .keylen       (keylen_i),
    .block        (block_i),
    .result       (result_o),
    .result_valid (result_valid_o)
  );

  // ------------------------------------------------------------------------
  // Test Stimulus
  // ------------------------------------------------------------------------
  initial begin
    $dumpfile("tb_aes_smoke.vcd");
    $dumpvars(0, tb_aes_smoke);

    // 1. Initialize Default States
    encdec_i = 1'b1;  // 1 = Encrypt
    init_i   = 1'b0;
    next_i   = 1'b0;
    key_i    = 256'h0;
    keylen_i = 1'b0;  // 0 = AES-128
    block_i  = 128'h0;

    // 2. Assert and Release Reset
    #20;
    rst_ni = 1'b1;
    @(posedge clk_i);

    // 3. Load Key (One-shot at boot)
    // For AES-128, secworks expects the key in the upper 128 bits of the 256-bit bus
    key_i  = {128'h2b7e151628aed2a6abf7158809cf4f3c, 128'h0};
    init_i = 1'b1;
    @(posedge clk_i);
    init_i = 1'b0;

    // Wait for key expansion to finish
    wait(ready_o == 1'b1);
    @(posedge clk_i);

    // 4. Load Plaintext Block & Pulse Next
    block_i = 128'h3243f6a8885a308d313198a2e0370734;
    next_i  = 1'b1;
    @(posedge clk_i);
    next_i  = 1'b0;

    // Wait for encryption to finish (~12 cycles)
    wait(result_valid_o == 1'b1);

    // 5. Evaluate Result
    if (result_o == 128'h3925841d02dc09fbdc118597196a0b32) begin
      $display("\n========================================");
      $display(" PASS: secworks aes_core smoke test");
      $display("========================================\n");
    end else begin
      $display("\n========================================");
      $display(" FAIL: CT mismatch!");
      $display(" Expected : 3925841d02dc09fbdc118597196a0b32");
      $display(" Actual   : %h", result_o);
      $display("========================================\n");
    end

    #10 $finish;
  end

endmodule
