// Purpose: Verify specific FSM fixes (Timeout, Sticky Error, Key Zeroization, Bus Latch)
// Date: 2026-05-26

`timescale 1ns/1ps


module tb_aes_gcm_quickfix;
  // Default geometry of aes_gcm_top (AES-128, 256-byte page)
  localparam int KEY_W  = 128;
  localparam int IV_W   = 96;
  localparam int TAG_W  = 128;
  localparam int DATA_W = 128;
  localparam int AAD_W  = 128;
  import aes_gcm_pkg::*;

  localparam int CLK_HALF = 5; // 100 MHz clock

  // -------------------------------------------------------------------------
  // DUT Ports
  // -------------------------------------------------------------------------
  logic              clk_i;
  logic              rst_ni;

  logic              start_i;
  logic              encdec_i;
  logic [KEY_W-1:0]  key_i;
  logic [IV_W-1:0]   iv_i;
  logic [AAD_W-1:0]  aad_i;
  logic [TAG_W-1:0]  exp_tag_i;

  logic              data_valid_i;
  logic              data_ready_o;

  logic              done_o;
  logic              tag_match_o;
  logic [TAG_W-1:0]  tag_o;
  logic [KEY_W-1:0]  aes_key_o;

  logic              aes_ready_i;
  logic              aes_valid_i;
  logic [DATA_W-1:0] aes_result_i;
  logic              aes_init_o;
  logic              aes_next_o;
  logic [DATA_W-1:0] aes_block_o;

  logic              ghash_init_o;
  logic              ghash_valid_o;
  logic              ghash_sel_ct_o;
  logic [DATA_W-1:0] ghash_hash_o;
  logic [DATA_W-1:0] ghash_fsm_data_o;
  logic              ghash_ready_i;
  logic [DATA_W-1:0] ghash_result_i;

  logic              block_out_valid_o;
  logic              last_block_o;
  logic              key_consumed_o;
  logic              fsm_err_o;
  logic              busy_o;
  logic              aad_valid_i;
  logic              aad_ready_o;
  logic              data_out_ready_i;

  // -------------------------------------------------------------------------
  // DUT Instantiation
  // -------------------------------------------------------------------------
  aes_gcm_fsm dut (.*);

  // -------------------------------------------------------------------------
  // Clock Generation & Global Timeout
  // -------------------------------------------------------------------------
  initial clk_i = 1'b0;
  always #CLK_HALF clk_i = ~clk_i;

  initial begin
    #200_000;
    $display("\n========================================");
    $display("FAIL: GLOBAL TIMEOUT — Simulation Halted");
    $display("========================================\n");
    $finish;
  end

  // -------------------------------------------------------------------------
  // Cycle-Accurate Mocks for AES Core and GHASH (Verilator Safe)
  // -------------------------------------------------------------------------
  logic [3:0] aes_cnt;
  logic       aes_busy;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      aes_ready_i  <= 1'b1;
      aes_valid_i  <= 1'b0;
      aes_busy     <= 1'b0;
      aes_cnt      <= '0;
      aes_result_i <= 128'h2; // Mock EJ0 as 2
    end else if (!aes_busy && (aes_init_o || aes_next_o)) begin
      aes_ready_i <= 1'b0;
      aes_valid_i <= 1'b0; // Drops immediately on new operation
      aes_busy    <= 1'b1;
      aes_cnt     <= 4'd4;
    end else if (aes_busy) begin
      if (aes_cnt == 0) begin
        aes_busy    <= 1'b0;
        aes_ready_i <= 1'b1;
        aes_valid_i <= 1'b1; // Stays high until next operation (secworks spec)
      end else begin
        aes_cnt <= aes_cnt - 4'd1;
      end
    end
  end

  logic [3:0] ghash_cnt;
  logic       ghash_busy;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      ghash_ready_i  <= 1'b1;
      ghash_busy     <= 1'b0;
      ghash_cnt      <= '0;
      ghash_result_i <= 128'hAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_1111_2222;
    end else if (!ghash_busy && ghash_valid_o) begin
      ghash_ready_i <= 1'b0;
      ghash_busy    <= 1'b1;
      ghash_cnt     <= 4'd4;
    end else if (ghash_busy) begin
      if (ghash_cnt == 0) begin
        ghash_busy    <= 1'b0;
        ghash_ready_i <= 1'b1;
      end else begin
        ghash_cnt <= ghash_cnt - 4'd1;
      end
    end
  end

  // -------------------------------------------------------------------------
  // Assertion Tasks
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

  task automatic chk_vec(input string name, input logic [127:0] got, input logic [127:0] exp);
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
  // Test Sequence
  // -------------------------------------------------------------------------
  initial begin
    $dumpfile("fsm_chat_fixes.vcd");
    $dumpvars(0, tb_aes_gcm_quickfix);

    $display("=== tb_aes_gcm_quickfix: Verifying FSM Hotfixes ===");

    // 0. Reset
    rst_ni       = 1'b0;
    start_i      = 1'b0;
    encdec_i     = 1'b0; // Decrypt
    aad_valid_i      = 1'b0;
    data_out_ready_i = 1'b1;
    data_valid_i     = 1'b0;
    key_i        = 128'hCAFE_F00D_DEAD_BEEF_CAFE_F00D_DEAD_BEEF;
    iv_i         = 96'h12345678_9ABCDEF0_11223344;
    aad_i        = 128'hA1A2A3A4_B1B2B3B4_C1C2C3C4_D1D2D3D4;
    exp_tag_i    = 128'hAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_1111_2222 ^ 128'h2; // GHASH ^ EJ0

    repeat (4) @(posedge clk_i);
    rst_ni = 1'b1;
    @(posedge clk_i);

    // =======================================================================
    // TEST 1: Key Zeroization (Issue #10), Bus Latch (Issue #17), Tag Match (Issue #9)
    // =======================================================================
    $display("\n--- TEST 1: Normal Run (Key Clear, Bus Latch, Tag Check) ---");
    start_i     = 1'b1;
    aad_valid_i = 1'b1;  // assert with start; deassert after FSM pulses aad_ready_o
    fork
      begin
        @(posedge aad_ready_o);
        @(posedge clk_i); #1;
        aad_valid_i = 1'b0;
      end
    join_none
    @(posedge clk_i);
    start_i = 1'b0;

    wait(key_consumed_o == 1'b1);
    @(posedge clk_i); 
    @(posedge clk_i); 
    chk_vec("Key bus zeroized after KEY_INIT", aes_key_o, 128'h0);

    wait(dut.state_q == dut.ST_PROC_PAYLOAD);
    @(posedge clk_i);
    chk_vec("ghash_fsm_data_o stably holding AAD", ghash_fsm_data_o, aad_i);

    data_valid_i = 1'b1;

    wait(done_o == 1'b1);
    data_valid_i = 1'b0;
    
    chk_bit("tag_match_o registered and asserted high", tag_match_o, 1'b1);
    @(posedge clk_i);


    // =======================================================================
    // TEST 2: Watchdog Timeout & Sticky Error (Issues #5 & #6)
    // =======================================================================
    $display("\n--- TEST 2: Data Starvation & Watchdog Recovery ---");
    start_i     = 1'b1;
    aad_valid_i = 1'b1;  // assert with start; deassert after FSM pulses aad_ready_o
    fork
      begin
        @(posedge aad_ready_o);
        @(posedge clk_i); #1;
        aad_valid_i = 1'b0;
      end
    join_none
    @(posedge clk_i);
    start_i = 1'b0;

    wait(dut.state_q == dut.ST_PROC_PAYLOAD);
    $display("  [INFO] FSM in ST_PROC_PAYLOAD. Withholding data...");
    
    #42000;
    @(posedge clk_i);

    chk_bit("Watchdog tripped, fsm_err_o sticky bit set", fsm_err_o, 1'b1);
    chk_bit("FSM broke deadlock, returned to IDLE (busy_o = 0)", busy_o, 1'b0);

    $display("\n--- TEST 3: Sticky Error Clear ---");
    start_i = 1'b1;
    @(posedge clk_i);
    start_i = 1'b0;
    @(posedge clk_i);
    chk_bit("Sticky error fsm_err_o cleared on fresh start_i", fsm_err_o, 1'b0);

    // =======================================================================
    // Summary
    // =======================================================================
    $display("\n=== %0d passed, %0d failed ===", pass_count, fail_count);
    if (fail_count == 0)
      $display("ALL TESTS PASSED");
    else
      $display("TESTS FAILED");
      
    $finish;
  end
endmodule
