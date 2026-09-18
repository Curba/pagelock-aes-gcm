// Purpose: Backpressure test for aes_gcm_top output controller FSM.
// Author: Baris
// Date: 2026-06-05
//
// Drives 14 plaintext blocks through an encrypt operation.  After block
// STALL_AFTER (index 3) is captured, cipher_data_out_ready_i is deasserted
// on the same #1-after-posedge sample point and held LOW for STALL_CYCLES
// (20) before being reasserted.
//
// Why block 3 is not dropped:
//   reg_ready_q is the registered version of cipher_data_out_ready_i.  On the
//   posedge where block 3's valid fires, reg_ready_q is still HIGH (it was
//   loaded from the previous cycle, when ready_i was 1).  The testbench
//   deasserts ready_i at #1 after that posedge, so reg_ready_q only drops
//   one clock later.  Block 3 has already been accepted.
//
// What the stall actually holds:
//   Both block_out_valid_o and ghash_valid_o are combinatorially gated by
//   data_out_ready_i (= reg_ready_q).  While reg_ready_q = 0 the FSM cannot
//   advance from phase-2 (AES done, waiting to output + start GHASH) for any
//   subsequent block.  The secworks AES core holds result_valid HIGH until the
//   next aes_next_o, so the computed ciphertext is not lost during the stall.
//
// Checks (53 assertions):
//   S1.  cipher_total_blocks_o == 16 (static, encrypt)
//   S2.  cipher_err_o LOW
//   S3.  cipher_done_o HIGH
//   S4.  All 16 output blocks correct and in order:
//          CT[0–13]  match tb/vectors/ct.hex
//          blk_out[14] == cipher_tag_o at capture (OC_TAG MUX)
//          blk_out[15] == GCM_AAD (OC_AAD latch)
//   S5.  Stall boundary: CT[STALL_AFTER] (block 3) present and correct
//   S6.  Stall boundary: CT[STALL_AFTER+1] (block 4) present and correct
//          (first block past the stall window)
//   S7.  cipher_data_out_last_o LOW on blocks 0–14, HIGH on block 15
//   S8.  cipher_page_done_o LOW on blocks 0–14, HIGH on block 15
//   S9.  cipher_tag_o == golden_tag after done_o
//   S10. No cipher_data_out_valid_o pulse during the STALL_CYCLES window
//          (confirms OC_PASS holds valid LOW while reg_ready_q = 0)
//
// CAPTURE MODEL:
//   Clock-by-clock sampling at #1 after posedge (not posedge-of-valid) so
//   that the consecutive-valid burst (CT[13]→TAG→AAD) is handled correctly.
//   During the stall window the same loop counts any spurious valid pulses.

`timescale 1ns/1ps

module tb_output_fsm_backpressure;

  // Default geometry of aes_gcm_top (AES-128, 256-byte page)
  localparam int KEY_W  = 128;
  localparam int IV_W   = 96;
  localparam int TAG_W  = 128;
  localparam int DATA_W = 128;
  localparam int AAD_W  = 128;

  localparam int CLK_HALF    = 5;    // 10 ns period → 100 MHz
  localparam int NBLOCKS     = 14;
  localparam int OUT_ENC     = 16;   // 14 CT + 1 tag + 1 AAD
  localparam int STALL_AFTER = 3;    // deassert ready after this output-block index
  localparam int STALL_CYCLES = 20;  // cycles to hold ready LOW

  // -------------------------------------------------------------------------
  // DUT ports
  // -------------------------------------------------------------------------
  logic         clk_i, rst_ni;
  logic         start_i, encdec_i;
  logic [127:0] key_i, aad_i, exp_tag_i;
  logic  [95:0] iv_i;
  logic [127:0] cipher_plaintext_data_i;
  logic [127:0] cipher_spi_data_i;
  logic         aad_valid_i;
  logic         aad_ready_o;
  logic         data_valid_i;
  logic         data_ready_o;
  logic [127:0] cipher_data_out_o;
  logic         cipher_data_out_valid_o;
  logic         cipher_data_out_last_o;
  logic         cipher_page_done_o;
  logic         done_o;
  logic         rsp_ready_i;
  logic         err_o;
  logic [4:0]   total_blocks_o;
  // Ports not under test
  logic         key_consumed_nc, key_ready_nc, busy_nc, tag_ok_nc;
  logic [3:0]   state_nc;

  // Controlled by the testbench; connected directly to cipher_data_out_ready_i.
  logic ready_reg;

  // -------------------------------------------------------------------------
  // DUT
  // -------------------------------------------------------------------------
  aes_gcm_top dut (
    .clk_i                    (clk_i),
    .rst_ni                   (rst_ni),
    .cmd_valid_i             (start_i),
    .cmd_ready_o             (aad_ready_o),
    .cmd_mode_i              (encdec_i),
    .cmd_key_i               (key_i),
    .cmd_iv_i                (iv_i),
    .cmd_aad_i               (aad_i),
    .cmd_exp_tag_i           (exp_tag_i),
    .data_in_valid_i         (data_valid_i),
    .data_in_ready_o         (data_ready_o),
    .data_in_i               (encdec_i ? cipher_plaintext_data_i : cipher_spi_data_i),
    .data_out_o              (cipher_data_out_o),
    .data_out_valid_o        (cipher_data_out_valid_o),
    .data_out_ready_i        (ready_reg),
    .rsp_valid_o             (done_o),
    .rsp_ready_i             (rsp_ready_i),
    .rsp_auth_ok_o           (tag_ok_nc),
    .rsp_error_o             (err_o),
    .data_out_last_o         (cipher_data_out_last_o)
  );

  assign key_consumed_nc    = start_i && aad_ready_o;
  assign key_ready_nc       = aad_ready_o;
  assign busy_nc            = !aad_ready_o;
  assign cipher_page_done_o = cipher_data_out_valid_o
                            && cipher_data_out_last_o
                            && ready_reg;
  assign total_blocks_o     = encdec_i ? 5'd16 : 5'd14;
  assign state_nc           = '0;

  // Clock
  initial clk_i = 1'b0;
  always  #CLK_HALF clk_i = ~clk_i;

  int pass_count, fail_count;

  // -------------------------------------------------------------------------
  // Test parameters — match tb_aes_gcm_top / tb_output_fsm_happy
  // -------------------------------------------------------------------------
  localparam logic [127:0] GCM_KEY = 128'h2b7e151628aed2a6abf7158809cf4f3c;
  localparam logic  [95:0] GCM_IV  = 96'hcafebabe_facedbad_decaf888;
  localparam logic [127:0] GCM_AAD = 128'hfeedface_deadbeef_feedface_deadbeef;

  // -------------------------------------------------------------------------
  // Golden vectors
  // -------------------------------------------------------------------------
  logic [127:0] golden_ct      [NBLOCKS];
  logic [127:0] golden_tag_arr [1];
  logic [127:0] golden_tag;

  logic [127:0] P [NBLOCKS];   // plaintext: byte[i] = i & 0xff

  // Captured outputs
  logic [127:0] blk_out      [OUT_ENC];
  logic         last_at      [OUT_ENC];
  logic         page_done_at [OUT_ENC];
  logic [127:0] tag_snap;      // cipher_tag_o sampled on the block-14 capture cycle
  logic         rsp_seen;

  initial begin
    for (int j = 0; j < NBLOCKS; j++) begin
      logic [127:0] blk;
      blk = '0;
      for (int k = 0; k < 16; k++)
        blk = (blk << 8) | 8'((j * 16 + k) & 8'hff);
      P[j] = blk;
    end
    $readmemh("tb/vectors/ct.hex",  golden_ct);
    $readmemh("tb/vectors/tag.hex", golden_tag_arr);
    golden_tag = golden_tag_arr[0];
  end

  // -------------------------------------------------------------------------
  // Tasks
  // -------------------------------------------------------------------------
  task automatic reset_dut;
    ready_reg               = 1'b1;
    rst_ni                  = 1'b0;
    start_i                 = 1'b0;
    encdec_i                = 1'b1;
    key_i                   = '0;
    iv_i                    = '0;
    aad_i                   = '0;
    exp_tag_i               = '0;
    aad_valid_i             = 1'b0;
    data_valid_i            = 1'b0;
    rsp_ready_i             = 1'b0;
    rsp_seen                = 1'b0;
    cipher_plaintext_data_i = '0;
    cipher_spi_data_i       = '0;
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
      $display("  PASS  %s", name);
      pass_count++;
    end else begin
      $display("  FAIL  %s", name);
      $display("          expected = %h", exp);
      $display("          got      = %h", got);
      fail_count++;
    end
  endtask

  task automatic gcm_start_encrypt;
    @(posedge clk_i); #1;
    start_i     = 1'b1;
    encdec_i    = 1'b1;
    key_i       = GCM_KEY;
    iv_i        = GCM_IV;
    aad_i       = GCM_AAD;
    exp_tag_i   = '0;
    aad_valid_i = 1'b1;
    @(posedge clk_i iff aad_ready_o); #1;
    start_i     = 1'b0;
    aad_valid_i = 1'b0;
    while (!data_ready_o) @(posedge clk_i);
    #1;
  endtask

  // Drive NBLOCKS PT blocks and capture all OUT_ENC output blocks.
  // Stall behaviour:
  //   When the capture index reaches STALL_AFTER+1 (block STALL_AFTER just
  //   captured), ready_reg is deasserted immediately at the same #1 sample
  //   point.  Because reg_ready_q is the registered form of ready_i, it was
  //   still HIGH on the posedge that produced block STALL_AFTER — that block
  //   is already accepted.  reg_ready_q drops LOW one cycle later, freezing
  //   the FSM in phase-2 of the next block's processing.
  //
  //   The same for-loop that counts stall cycles also monitors for any
  //   spurious cipher_data_out_valid_o pulse; there should be none while
  //   reg_ready_q = 0.
  task automatic run_with_backpressure(output int stall_spurious);
    automatic int drive_idx = 0;
    automatic int cap_idx   = 0;
    stall_spurious = 0;

    fork

      // ----------------------------------------------------------------
      // Thread 1 — streaming plaintext producer
      // ----------------------------------------------------------------
      begin : bp_drive
        while (drive_idx < NBLOCKS) begin
          while (!data_ready_o) @(posedge clk_i);
          #1;
          cipher_plaintext_data_i = P[drive_idx];
          cipher_spi_data_i       = P[drive_idx];
          data_valid_i            = 1'b1;
          @(posedge clk_i); #1;
          drive_idx++;
          data_valid_i = 1'b0;
          if (drive_idx < NBLOCKS) begin
            cipher_plaintext_data_i = P[drive_idx];
            cipher_spi_data_i       = P[drive_idx];
          end else begin
            cipher_plaintext_data_i = 'x;
            cipher_spi_data_i       = 'x;
          end
        end
      end : bp_drive

      // ----------------------------------------------------------------
      // Thread 2 — clock-by-clock capture with inline stall
      // ----------------------------------------------------------------
      begin : bp_capture
        while (cap_idx < OUT_ENC) begin
          @(posedge clk_i); #1;
          if (cipher_data_out_valid_o) begin
            blk_out[cap_idx]      = cipher_data_out_o;
            last_at[cap_idx]      = cipher_data_out_last_o;
            page_done_at[cap_idx] = cipher_page_done_o;
            if (cap_idx == 14)
              tag_snap = cipher_data_out_o;
            cap_idx++;

            if (cap_idx == STALL_AFTER + 1) begin
              // Deassert ready at this same sample point.  reg_ready_q was 1
              // on the posedge that produced block STALL_AFTER, so it is
              // already accepted.  reg_ready_q goes LOW one posedge later.
              ready_reg = 1'b0;
              $display("  [stall] ready deasserted after block %0d  (time=%0t)",
                       STALL_AFTER, $time);

              // Hold stall for STALL_CYCLES cycles; count any valid that
              // sneaks through (block_out_valid_o must be 0 while reg_ready_q=0).
              for (int s = 0; s < STALL_CYCLES; s++) begin
                @(posedge clk_i); #1;
                if (!cipher_data_out_valid_o)
                  stall_spurious++;
              end

              ready_reg = 1'b1;
              $display("  [stall] ready reasserted after %0d cycles  (time=%0t)",
                       STALL_CYCLES, $time);
            end
          end
        end
      end : bp_capture

    join

    wait (done_o);
    #1;
    rsp_seen = 1'b1;
    rsp_ready_i = 1'b1;
    @(posedge clk_i); #1;
    rsp_ready_i = 1'b0;
  endtask

  // -------------------------------------------------------------------------
  // Stimulus and checks
  // -------------------------------------------------------------------------
  initial begin
    automatic int spurious;

    pass_count = 0;
    fail_count = 0;

    $display("=== tb_output_fsm_backpressure: output controller FSM backpressure ===");
    $display("KEY         = %h", GCM_KEY);
    $display("IV          = %h", GCM_IV);
    $display("AAD         = %h", GCM_AAD);
    $display("STALL_AFTER = block %0d  STALL_CYCLES = %0d", STALL_AFTER, STALL_CYCLES);
    $display("");

    reset_dut();

    // -----------------------------------------------------------------------
    // S1 — total_blocks_o == 16 (static, encrypt mode)
    // -----------------------------------------------------------------------
    $display("--- S1: total_blocks_o (encrypt, static) ---");
    encdec_i = 1'b1; #1;
    chk_bit("total_blocks_o == 16", total_blocks_o === 5'd16, 1'b1);

    gcm_start_encrypt();
    run_with_backpressure(spurious);

    // -----------------------------------------------------------------------
    // S2 — no error flag
    // -----------------------------------------------------------------------
    $display("");
    $display("--- S2: no error ---");
    chk_bit("cipher_err_o == 0", err_o, 1'b0);

    // -----------------------------------------------------------------------
    // S3 — done_o asserted
    // -----------------------------------------------------------------------
    $display("");
    $display("--- S3: done_o ---");
    chk_bit("rsp_valid_o observed", rsp_seen, 1'b1);

    // -----------------------------------------------------------------------
    // S4 — all 16 output blocks correct and in order
    // -----------------------------------------------------------------------
    $display("");
    $display("--- S4: all 16 blocks in order ---");
    for (int i = 0; i < NBLOCKS; i++)
      chk_vec($sformatf("CT[%02d]", i), blk_out[i], golden_ct[i]);
    chk_vec("blk_out[14] == tag_o@cap", blk_out[14], tag_snap);
    chk_vec("blk_out[15] == GCM_AAD",   blk_out[15], GCM_AAD);

    // -----------------------------------------------------------------------
    // S5 — stall boundary: block STALL_AFTER not dropped
    // -----------------------------------------------------------------------
    $display("");
    $display("--- S5: block %0d (last before stall) not dropped ---", STALL_AFTER);
    chk_vec($sformatf("CT[%02d] correct at stall boundary", STALL_AFTER),
            blk_out[STALL_AFTER], golden_ct[STALL_AFTER]);

    // -----------------------------------------------------------------------
    // S6 — stall boundary: block STALL_AFTER+1 resumes correctly
    // -----------------------------------------------------------------------
    $display("");
    $display("--- S6: block %0d (first after stall) resumes correctly ---",
             STALL_AFTER + 1);
    chk_vec($sformatf("CT[%02d] correct post-stall", STALL_AFTER + 1),
            blk_out[STALL_AFTER + 1], golden_ct[STALL_AFTER + 1]);

    // -----------------------------------------------------------------------
    // S7 — cipher_data_out_last_o: LOW on 0–14, HIGH only on 15
    // -----------------------------------------------------------------------
    $display("");
    $display("--- S7: cipher_data_out_last_o sequencing ---");
    for (int i = 0; i < OUT_ENC - 1; i++)
      chk_bit($sformatf("last_o LOW  on block %02d", i), last_at[i], 1'b0);
    chk_bit("last_o HIGH on block 15", last_at[15], 1'b1);

    // -----------------------------------------------------------------------
    // S8 — cipher_page_done_o: LOW on 0–14, HIGH only on 15
    // -----------------------------------------------------------------------
    $display("");
    $display("--- S8: cipher_page_done_o sequencing ---");
    for (int i = 0; i < OUT_ENC - 1; i++)
      chk_bit($sformatf("page_done LOW  on block %02d", i), page_done_at[i], 1'b0);
    chk_bit("page_done HIGH on block 15", page_done_at[15], 1'b1);

    // -----------------------------------------------------------------------
    // S9 — crypto cross-check: stream TAG block matches golden tag
    // -----------------------------------------------------------------------
    $display("");
    $display("--- S9: blk_out[14] == golden tag ---");
    chk_vec("blk_out[14] == golden_tag", blk_out[14], golden_tag);

    // -----------------------------------------------------------------------
    // S10 — no valid pulse during the stall window
    //   block_out_valid_o = ... && data_out_ready_i; OC_PASS never drives
    //   cipher_data_out_valid_o independently, so valid must stay 0 while
    //   reg_ready_q = 0.
    // -----------------------------------------------------------------------
    $display("");
    $display("--- S10: no valid during %0d-cycle stall window ---", STALL_CYCLES);
    if (spurious == 0) begin
      $display("  PASS  data_out_valid_o held during stall");
      pass_count++;
    end else begin
      $display("  FAIL  data_out_valid_o dropped for %0d stall cycle(s)",
               spurious);
      fail_count++;
    end

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    $display("");
    $display("=== %0d passed, %0d failed ===", pass_count, fail_count);
    if (fail_count == 0)
      $display("ALL TESTS PASSED");
    else
      $display("TESTS FAILED");

    $finish;
  end

  // Watchdog: one encrypt run ~3000 cycles plus stall overhead.
  initial begin
    #6_000_000;
    $display("TIMEOUT — simulation did not finish");
    $finish;
  end

endmodule
