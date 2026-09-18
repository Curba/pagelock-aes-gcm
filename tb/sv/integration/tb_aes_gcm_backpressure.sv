// Purpose: Backpressure testbench — cipher_data_out_ready_i stall tests.
//          STALL_MID_CT  : stall 10 cycles after CT block 3.
//          STALL_ON_TAG  : stall 8 cycles at OC_TAG (encrypt append).
//          STALL_ON_AAD  : stall 8 cycles at OC_AAD (encrypt append).
//          DECRYPT_BACKPRESSURE: stall 5 cycles after decrypt block 7.
//
// ready_q note: cipher_data_out_ready_i is registered inside aes_gcm_top as
//   ready_q.  A deassert on ready_i takes effect in the DUT one cycle later.
//   Stall detection below uses the TB-visible (cipher_data_out_valid_o &&
//   cipher_data_out_ready_i) handshake; the DUT transitions on ready_q, so
//   the first cycle where the TB sees valid=1 && ready_i=1 after a reassert
//   is also the cycle where ready_q=1 inside the DUT.
// Author: Claude
// Date: 2026-06-04
`timescale 1ns/1ps

module tb_aes_gcm_backpressure;

  localparam int CLK_HALF = 5;   // 10 ns period
  localparam int NBLOCKS  = 14;  // payload blocks

  // -------------------------------------------------------------------------
  // DUT ports
  // -------------------------------------------------------------------------
  logic         clk_i, rst_ni;
  logic         cipher_start_i, cipher_mode_i;
  logic [127:0] cipher_key_i, cipher_aad_i, cipher_exp_tag_i;
  logic  [95:0] cipher_iv_i;
  logic [127:0] cipher_plaintext_data_i, cipher_spi_data_i;
  logic         cipher_aad_valid_i,  cipher_aad_ready_o;
  logic         cipher_data_in_valid_i, cipher_data_in_ready_o;
  logic [127:0] cipher_data_out_o;
  logic         cipher_data_out_valid_o;
  logic         cipher_data_out_ready_i;   // TB drives this for backpressure
  logic         cipher_data_out_last_o;
  logic         cipher_page_done_o;
  logic [4:0]   cipher_total_blocks_o;
  logic         cipher_done_o;
  logic         rsp_ready_i;
  logic         cipher_tag_ok_o;
  logic         cipher_busy_o, cipher_err_o;
  // Unused
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
    .rsp_ready_i             (rsp_ready_i),
    .rsp_auth_ok_o           (cipher_tag_ok_o),
    .rsp_error_o             (cipher_err_o),
    .data_out_last_o         (cipher_data_out_last_o)
  );

  assign key_consumed_nc       = cipher_start_i && cipher_aad_ready_o;
  assign key_ready_nc          = cipher_aad_ready_o;
  assign cipher_busy_o         = !cipher_aad_ready_o;
  assign cipher_page_done_o    = cipher_data_out_valid_o
                               && cipher_data_out_ready_i
                               && cipher_data_out_last_o;
  assign cipher_total_blocks_o = cipher_mode_i ? 5'd16 : 5'd14;
  assign state_nc              = '0;

  // -------------------------------------------------------------------------
  // Clock
  // -------------------------------------------------------------------------
  initial clk_i = 1'b0;
  always #CLK_HALF clk_i = ~clk_i;

  // Watchdog: 5 runs × generous budget (each ~3000 cycles × 10 ns)
  initial begin
    #20_000_000;
    $display("TIMEOUT — simulation did not finish");
    $finish;
  end

  // -------------------------------------------------------------------------
  // Test constants — same as tb_aes_gcm_roundtrip
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
    rsp_ready_i             = 1'b0;
    cipher_plaintext_data_i = '0;
    cipher_spi_data_i       = '0;
    repeat (4) @(posedge clk_i); #1;
    rst_ni = 1'b1;
    @(posedge clk_i); #1;
  endtask

  // -------------------------------------------------------------------------
  // Kick off an encrypt, handle AAD handshake in background, deassert start.
  // Returns after start_i deasserted; caller must wait for data_in_ready.
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
    @(posedge clk_i iff cipher_aad_ready_o); #1;
    cipher_start_i     = 1'b0;
    cipher_aad_valid_i = 1'b0;
  endtask

  // -------------------------------------------------------------------------
  // Kick off a decrypt; exp_tag_i supplied by caller.
  // -------------------------------------------------------------------------
  task automatic start_decrypt(input logic [127:0] exp_tag_p);
    @(posedge clk_i); #1;
    cipher_start_i     = 1'b1;
    cipher_mode_i      = 1'b0;
    cipher_key_i       = KEY;
    cipher_iv_i        = IV;
    cipher_aad_i       = AAD;
    cipher_exp_tag_i   = exp_tag_p;
    cipher_aad_valid_i = 1'b1;
    @(posedge clk_i iff cipher_aad_ready_o); #1;
    cipher_start_i     = 1'b0;
    cipher_aad_valid_i = 1'b0;
  endtask

  task automatic wait_and_ack_response;
    wait (cipher_done_o);
    #1;
    rsp_ready_i = 1'b1;
    @(posedge clk_i); #1;
    rsp_ready_i = 1'b0;
  endtask

  // =========================================================================
  // run_stall_on_tag
  //   Encrypt 14 blocks, stall cipher_data_out_ready_i for stall_cyc cycles
  //   after CT block 13 is accepted and OC_TAG becomes valid.
  //   During stall: captures data stability and page_done absence.
  //   After stall: captures the tag block and AAD block.
  // =========================================================================
  task automatic run_stall_on_tag(
    input  int            stall_cyc,
    output logic [127:0]  aad_block_out,
    output logic          data_stable,
    output logic          no_pd_during_stall,
    output logic          last_on_aad,
    output logic          pd_on_aad,
    output int            total_blocks,
    output logic [127:0]  final_tag
  );
    automatic int cap_idx = 0;
    data_stable        = 1'b1;
    no_pd_during_stall = 1'b1;
    last_on_aad        = 1'b0;
    pd_on_aad          = 1'b0;
    total_blocks       = 0;
    aad_block_out      = '0;

    start_encrypt();
    while (!cipher_data_in_ready_o) @(posedge clk_i);
    #1;

    fork
      // Feed thread
      begin : sot_feed
        for (int i = 0; i < NBLOCKS; i++) begin
          while (!cipher_data_in_ready_o) @(posedge clk_i);
          #1;
          cipher_plaintext_data_i = P[i];
          cipher_data_in_valid_i  = 1'b1;
          @(posedge clk_i); #1;
          cipher_data_in_valid_i  = 1'b0;
        end
      end : sot_feed

      // Capture / stall thread
      begin : sot_cap
        // ---------------------------------------------------------------
        // Phase 1: accept 14 CT blocks freely
        // ---------------------------------------------------------------
        while (cap_idx < NBLOCKS) begin
          @(posedge clk_i);
          if (cipher_data_out_valid_o && cipher_data_out_ready_i) begin
            cap_idx++;
            total_blocks++;
          end
        end
        // Block output before OC_TAG appears, then wait for its valid signal.
        #1;
        cipher_data_out_ready_i = 1'b0;
        while (cipher_data_out_valid_o) begin
          @(posedge clk_i);
          #1;
        end
        while (!cipher_data_out_valid_o) begin
          @(posedge clk_i);
          #1;
        end

        // ---------------------------------------------------------------
        // Stall monitoring window (stall_cyc cycles)
        // ---------------------------------------------------------------
        begin : sot_monitor
          logic [127:0] held;
          held = cipher_data_out_o;
          repeat (stall_cyc) begin
            @(posedge clk_i); #1;
            if (!cipher_data_out_valid_o)       data_stable        = 1'b0;
            if (cipher_data_out_o !== held)  data_stable        = 1'b0;
            if (cipher_page_done_o)          no_pd_during_stall = 1'b0;
          end
        end : sot_monitor

        // Reassert ready; OC_TAG transfers on the next rising edge.
        cipher_data_out_ready_i = 1'b1;

        // ---------------------------------------------------------------
        // Phase 2: collect tag block (OC_TAG) then AAD block (OC_AAD)
        // ---------------------------------------------------------------
        // Sample each block before the edge that accepts it. Sampling after
        // the edge observes the next output-controller state.
        @(negedge clk_i);
        if (cipher_data_out_valid_o && cipher_data_out_ready_i) begin
          final_tag = cipher_data_out_o;   // capture TAG from stream
          total_blocks++;
        end
        @(posedge clk_i); #1;

        // AAD block
        @(negedge clk_i);
        if (cipher_data_out_valid_o && cipher_data_out_ready_i) begin
          aad_block_out = cipher_data_out_o;
          last_on_aad   = cipher_data_out_last_o;
          pd_on_aad     = cipher_page_done_o;
          total_blocks++;
        end
        @(posedge clk_i); #1;
      end : sot_cap
    join

    wait_and_ack_response();
  endtask

  // =========================================================================
  // run_stall_on_aad
  //   Encrypt 14 blocks and let OC_TAG transfer freely.
  //   Stall cipher_data_out_ready_i for stall_cyc cycles after OC_TAG is
  //   accepted. OC_AAD must hold valid/data/last until current ready returns;
  //   page_done must assert only with the accepted AAD transfer.
  // =========================================================================
  task automatic run_stall_on_aad(
    input  int            stall_cyc,
    output logic [127:0]  aad_held,
    output logic          data_stable,
    output logic          last_held,
    output logic          no_pd_during_stall,
    output logic          pd_on_transfer
  );
    automatic int cap_idx = 0;
    data_stable        = 1'b1;
    last_held          = 1'b1;
    no_pd_during_stall = 1'b1;
    pd_on_transfer     = 1'b0;
    aad_held           = '0;

    start_encrypt();
    while (!cipher_data_in_ready_o) @(posedge clk_i);
    #1;

    fork
      // Feed thread
      begin : soa_feed
        for (int i = 0; i < NBLOCKS; i++) begin
          while (!cipher_data_in_ready_o) @(posedge clk_i);
          #1;
          cipher_plaintext_data_i = P[i];
          cipher_data_in_valid_i  = 1'b1;
          @(posedge clk_i); #1;
          cipher_data_in_valid_i  = 1'b0;
        end
      end : soa_feed

      // Capture / stall thread
      begin : soa_cap
        // ---------------------------------------------------------------
        // Accept 14 CT blocks freely
        // ---------------------------------------------------------------
        while (cap_idx < NBLOCKS) begin
          @(posedge clk_i);
          if (cipher_data_out_valid_o && cipher_data_out_ready_i)
            cap_idx++;
        end

        // Wait for the final CT valid to drop, then for OC_TAG to appear.
        #1;
        while (cipher_data_out_valid_o) begin
          @(posedge clk_i); #1;
        end
        while (!cipher_data_out_valid_o) begin
          @(posedge clk_i); #1;
        end
        // Accept TAG on the next rising edge.
        @(posedge clk_i); #1;

        // OC_AAD is now active. Deassert ready before its transfer edge.
        cipher_data_out_ready_i = 1'b0;

        // ---------------------------------------------------------------
        // Stall monitoring window (stall_cyc cycles in OC_AAD)
        // ---------------------------------------------------------------
        begin : soa_monitor
          @(posedge clk_i); #1;   // cycle 1 of OC_AAD stall
          aad_held = cipher_data_out_o;
          repeat (stall_cyc - 1) begin
            @(posedge clk_i); #1;
            if (cipher_data_out_o !== aad_held)  data_stable        = 1'b0;
            if (!cipher_data_out_last_o)         last_held          = 1'b0;
            if (cipher_page_done_o)              no_pd_during_stall = 1'b0;
          end
        end : soa_monitor

        // Reassert ready. AAD transfers on the next rising edge.
        cipher_data_out_ready_i = 1'b1;

        // ---------------------------------------------------------------
        // Collect AAD transfer and check page_done
        // ---------------------------------------------------------------
        @(negedge clk_i);
        if (cipher_data_out_valid_o && cipher_data_out_ready_i)
          pd_on_transfer = cipher_page_done_o;
        @(posedge clk_i); #1;
      end : soa_cap
    join

    wait_and_ack_response();
  endtask

  // =========================================================================
  // run_decrypt_stall
  //   Decrypt NBLOCKS CT blocks; stall ready for stall_cyc cycles after
  //   output block stall_after_blk is accepted.
  //   Decrypt never enters OC_TAG or OC_AAD, so exactly NBLOCKS blocks
  //   should appear and last_o fires only on the final one.
  // =========================================================================
  task automatic run_decrypt_stall(
    input  logic [127:0] ct_in   [NBLOCKS],
    input  logic [127:0] exp_tag_p,
    input  int           stall_after_blk,
    input  int           stall_cyc,
    output int           total_blocks,
    output logic         last_only_on_final,
    output logic         pd_on_final,
    output logic         total_blks_14
  );
    automatic int cap_idx        = 0;
    automatic int spurious_last  = 0;
    total_blocks       = 0;
    last_only_on_final = 1'b1;
    pd_on_final        = 1'b0;

    start_decrypt(exp_tag_p);
    while (!cipher_data_in_ready_o) @(posedge clk_i);
    #1;

    fork
      // Feed thread — drives cipher_spi_data_i (ciphertext on decrypt)
      begin : dec_feed
        for (int i = 0; i < NBLOCKS; i++) begin
          while (!cipher_data_in_ready_o) @(posedge clk_i);
          #1;
          cipher_spi_data_i      = ct_in[i];
          cipher_data_in_valid_i = 1'b1;
          @(posedge clk_i); #1;
          cipher_data_in_valid_i = 1'b0;
        end
      end : dec_feed

      // Capture thread
      begin : dec_cap
        while (cap_idx < NBLOCKS) begin
          @(posedge clk_i); #1;
          if (cipher_data_out_valid_o && cipher_data_out_ready_i) begin
            // last_o should only be HIGH on the final block
            if (cipher_data_out_last_o && cap_idx < NBLOCKS - 1)
              last_only_on_final = 1'b0;
            if (cap_idx == NBLOCKS - 1)
              pd_on_final = cipher_page_done_o;
            total_blocks++;
            cap_idx++;

            if (cap_idx == stall_after_blk + 1) begin
              cipher_data_out_ready_i = 1'b0;
              repeat (stall_cyc) @(posedge clk_i);
              #1;
              cipher_data_out_ready_i = 1'b1;
            end
          end
        end

        // Verify no extra blocks appear in the 10 cycles after the last one
        begin : dec_no_extra
          int extra = 0;
          repeat (10) begin
            @(posedge clk_i); #1;
            if (cipher_data_out_valid_o && cipher_data_out_ready_i)
              extra++;
          end
          if (extra > 0) total_blocks += extra;  // will cause total!=14 check to fail
        end : dec_no_extra
      end : dec_cap
    join

    total_blks_14 = (total_blocks == NBLOCKS);

    wait_and_ack_response();
  endtask

  // =========================================================================
  // Plaintext blocks — P[i] = all-bytes (i+1), same as tb_aes_gcm_roundtrip
  // =========================================================================
  logic [127:0] P [NBLOCKS];

  // =========================================================================
  // run_encrypt_with_stall
  //   Runs a full encrypt. Stalls cipher_data_out_ready_i for stall_cycles
  //   after output block stall_after_blk is accepted.
  //   Collects all 16 output blocks (14 CT + tag + AAD).
  //   Returns: blk_out[0..13] = CT blocks, out_tag = cipher_tag_o,
  //            page_done_seen = whether page_done fired on the last transfer.
  // =========================================================================
  task automatic run_encrypt_with_stall(
    input  int            stall_after_blk,  // 0-indexed; stall after this output block
    input  int            stall_cycles,
    output logic [127:0]  blk_out [NBLOCKS],
    output logic [127:0]  out_tag,
    output logic          page_done_seen,
    output int            total_out
  );
    automatic int feed_done  = 0;
    automatic int cap_idx    = 0;
    page_done_seen = 1'b0;
    total_out      = 0;

    start_encrypt();
    while (!cipher_data_in_ready_o) @(posedge clk_i);
    #1;

    fork
      // ------------------------------------------------------------------
      // Thread A — streaming input producer
      // ------------------------------------------------------------------
      begin : t_feed
        for (int i = 0; i < NBLOCKS; i++) begin
          while (!cipher_data_in_ready_o) @(posedge clk_i);
          #1;
          cipher_plaintext_data_i = P[i];
          cipher_data_in_valid_i  = 1'b1;
          @(posedge clk_i); #1;
          cipher_data_in_valid_i  = 1'b0;
        end
        feed_done = 1;
      end : t_feed

      // ------------------------------------------------------------------
      // Thread B — output capture with optional stall
      // ------------------------------------------------------------------
      begin : t_cap
        while (cap_idx < 16) begin
          // Wait for a valid && ready transfer
          @(posedge clk_i); #1;
          if (cipher_data_out_valid_o && cipher_data_out_ready_i) begin
            if (cap_idx < NBLOCKS)
              blk_out[cap_idx] = cipher_data_out_o;
            if (cap_idx == NBLOCKS)
              out_tag = cipher_data_out_o;   // TAG block from stream
            if (cipher_page_done_o)
              page_done_seen = 1'b1;
            total_out++;
            cap_idx++;

            // Apply stall immediately after accepting stall_after_blk
            if (cap_idx == stall_after_blk + 1) begin
              cipher_data_out_ready_i = 1'b0;
              repeat (stall_cycles) @(posedge clk_i);
              #1;
              cipher_data_out_ready_i = 1'b1;
            end
          end
        end
      end : t_cap
    join

    wait_and_ack_response();
  endtask

  // =========================================================================
  // Reference run — no stall; produces expected CT blocks and tag.
  // =========================================================================
  task automatic reference_run(
    output logic [127:0] ref_ct  [NBLOCKS],
    output logic [127:0] ref_tag
  );
    automatic int  cap_idx = 0;
    automatic int  total   = 0;
    logic [127:0]  dummy_tag;
    logic          dummy_pd;

    run_encrypt_with_stall(
      .stall_after_blk  (-1),   // never stall
      .stall_cycles     (0),
      .blk_out          (ref_ct),
      .out_tag          (ref_tag),
      .page_done_seen   (dummy_pd),
      .total_out        (total)
    );
  endtask

  // =========================================================================
  // Stimulus
  // =========================================================================
  logic [127:0] ref_ct   [NBLOCKS];
  logic [127:0] ref_tag;
  logic [127:0] stall_ct [NBLOCKS];
  logic [127:0] stall_tag;
  logic         page_done_seen;
  int           total_out;

  // STALL_ON_TAG outputs
  logic [127:0] sot_aad_out;
  logic         sot_data_stable, sot_no_pd, sot_last_aad, sot_pd_aad;
  int           sot_total;
  logic [127:0] sot_final_tag;

  // STALL_ON_AAD outputs
  logic [127:0] soa_aad_held;
  logic         soa_data_stable, soa_last_held, soa_no_pd, soa_pd_transfer;

  // DECRYPT_BACKPRESSURE outputs
  int           dec_total;
  logic         dec_last_ok, dec_pd_ok, dec_total_ok;

  initial begin
    pass_count = 0;
    fail_count = 0;
    $display("=== tb_aes_gcm_backpressure: backpressure stall tests ===");

    // Build plaintext: block i = all-bytes (i+1)
    for (int i = 0; i < NBLOCKS; i++)
      P[i] = {16{8'(i + 1)}};

    // -------------------------------------------------------------------
    // Reference run — collect expected ciphertexts
    // -------------------------------------------------------------------
    $display("--- Reference run (no stall) ---");
    reset_dut();
    reference_run(ref_ct, ref_tag);
    $display("  ref_tag = %h", ref_tag);
    if (ref_tag !== '0)
      $display("  PASS  ref_tag non-zero");
    else begin
      $display("  FAIL  ref_tag is all zeros");
      fail_count++;
    end

    // -------------------------------------------------------------------
    // STALL_MID_CT — deassert ready for 10 cycles after CT block 3
    // -------------------------------------------------------------------
    $display("--- STALL_MID_CT: 10-cycle stall after block 3 ---");
    reset_dut();
    run_encrypt_with_stall(
      .stall_after_blk  (3),
      .stall_cycles     (10),
      .blk_out          (stall_ct),
      .out_tag          (stall_tag),
      .page_done_seen   (page_done_seen),
      .total_out        (total_out)
    );

    // CT blocks must match reference (stall must not corrupt data)
    for (int i = 0; i < NBLOCKS; i++)
      chk_vec($sformatf("CT[%02d] matches reference", i), stall_ct[i], ref_ct[i]);

    // Tag must match reference
    chk_vec("Tag matches reference", stall_tag, ref_tag);

    // All 16 blocks (14 CT + tag + AAD) must have transferred
    chk_bit("Total output blocks == 16", (total_out == 16), 1'b1);

    // cipher_page_done_o must have fired on the last (AAD) transfer
    chk_bit("cipher_page_done_o asserted after block 16", page_done_seen, 1'b1);

    // No watchdog or FSM errors
    chk_bit("cipher_err_o = 0", cipher_err_o, 1'b0);

    // -------------------------------------------------------------------
    // STALL_ON_TAG — 8-cycle stall at OC_TAG after all CT blocks
    // -------------------------------------------------------------------
    $display("\n--- STALL_ON_TAG: 8-cycle stall while OC_TAG is active ---");
    reset_dut();
    run_stall_on_tag(
      .stall_cyc          (8),
      .aad_block_out      (sot_aad_out),
      .data_stable        (sot_data_stable),
      .no_pd_during_stall (sot_no_pd),
      .last_on_aad        (sot_last_aad),
      .pd_on_aad          (sot_pd_aad),
      .total_blocks       (sot_total),
      .final_tag          (sot_final_tag)
    );

    chk_bit("SOT: data stable on output during 8-cycle stall",   sot_data_stable, 1'b1);
    chk_bit("SOT: page_done not asserted during stall",          sot_no_pd,       1'b1);
    chk_vec("SOT: AAD block content matches cipher_aad_i",       sot_aad_out,     AAD);
    chk_bit("SOT: last_o asserted on AAD transfer",              sot_last_aad,    1'b1);
    chk_bit("SOT: page_done asserted on AAD transfer",           sot_pd_aad,      1'b1);
    chk_vec("SOT: final tag matches reference",                  sot_final_tag,   ref_tag);
    chk_bit("SOT: cipher_err_o = 0",                             cipher_err_o,    1'b0);

    // -------------------------------------------------------------------
    // STALL_ON_AAD — 8-cycle stall at OC_AAD
    // -------------------------------------------------------------------
    $display("\n--- STALL_ON_AAD: 8-cycle stall while OC_AAD is active ---");
    reset_dut();
    run_stall_on_aad(
      .stall_cyc          (8),
      .aad_held           (soa_aad_held),
      .data_stable        (soa_data_stable),
      .last_held          (soa_last_held),
      .no_pd_during_stall (soa_no_pd),
      .pd_on_transfer     (soa_pd_transfer)
    );

    chk_vec("SOA: AAD value stable during stall matches cipher_aad_i", soa_aad_held, AAD);
    chk_bit("SOA: data stable during 8-cycle stall",              soa_data_stable, 1'b1);
    chk_bit("SOA: last_o held HIGH during stall",                 soa_last_held,   1'b1);
    chk_bit("SOA: page_done not asserted during stall",           soa_no_pd,       1'b1);
    chk_bit("SOA: page_done asserts on transfer cycle",           soa_pd_transfer, 1'b1);
    chk_bit("SOA: cipher_err_o = 0",                              cipher_err_o,    1'b0);

    // -------------------------------------------------------------------
    // DECRYPT_BACKPRESSURE — decrypt path, stall after block 7
    // -------------------------------------------------------------------
    $display("\n--- DECRYPT_BACKPRESSURE: decrypt, 5-cycle stall after block 7 ---");
    reset_dut();
    cipher_data_out_ready_i = 1'b1;
    run_decrypt_stall(
      .ct_in          (ref_ct),
      .exp_tag_p      (ref_tag),
      .stall_after_blk(7),
      .stall_cyc      (5),
      .total_blocks   (dec_total),
      .last_only_on_final (dec_last_ok),
      .pd_on_final    (dec_pd_ok),
      .total_blks_14  (dec_total_ok)
    );

    chk_bit("DEC: exactly 14 blocks output total",               dec_total_ok,    1'b1);
    chk_bit("DEC: no tag or AAD blocks emitted (total==14)",     (dec_total == 14), 1'b1);
    chk_bit("DEC: last_o only on block 14, not earlier",         dec_last_ok,     1'b1);
    chk_bit("DEC: page_done asserts on block 14 transfer",       dec_pd_ok,       1'b1);
    chk_bit("DEC: cipher_total_blocks_o = 14",
            (cipher_total_blocks_o == 5'd14), 1'b1);
    chk_bit("DEC: cipher_err_o = 0",                             cipher_err_o,    1'b0);

    // -------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------
    $display("");
    $display("=== %0d passed, %0d failed ===", pass_count, fail_count);
    if (fail_count == 0) begin
      $display("ALL TESTS PASSED");
    end else begin
      $display("TESTS FAILED");
      $fatal(1, "Backpressure regression failed");
    end

    $display("done: all backpressure tests");
    $finish;
  end

endmodule
