// Purpose: Roundtrip testbench — encrypt 14 blocks, decrypt, tamper-detect
// Author: Claude
// Date: 2026-05-09
//
// Three phases:
//   Phase 1 — Encrypt: 14 blocks of known plaintext → C[14] + enc_tag
//   Phase 2 — Decrypt (valid):   C[14] + enc_tag → P_dec recovers original; tag_match_o=1
//   Phase 3 — Decrypt (tampered): C[0] bit 0 flipped → tag_match_o=0
//
// Plaintext recovery (Phase 2, P_dec checks) relies only on CTR-mode symmetry
// and is independent of GHASH.  Authentication (tag_match_o checks) requires
// that the GHASH mux in aes_gcm_top routes cipher_plaintext_data_i — not ct_w —
// to aes_ghash during decrypt so that GHASH processes the incoming ciphertext in
// both directions.  If Phase 2's tag_match_o=1 check fails, update the mux:
//   ghash_data_w = ghash_sel_ct_w
//     ? (encdec_w ? ct_w : cipher_plaintext_data_i)
//     : fsm_ghash_data_w;

`timescale 1ns/1ps

module tb_aes_gcm_roundtrip;

  localparam int CLK_HALF = 5;  // 10 ns period

  // -------------------------------------------------------------------------
  // DUT ports
  // -------------------------------------------------------------------------
  logic         clk_i;
  logic         rst_ni;
  logic         start_i;
  logic         encdec_i;
  logic [127:0] key_i;
  logic  [95:0] iv_i;
  logic [127:0] aad_i;
  logic   [7:0] plen_i;   // kept for run_gcm compatibility; not wired to DUT
  logic [127:0] exp_tag_i;
  logic         data_valid_i;
  logic         data_ready_o;
  logic [127:0] cipher_plaintext_data_i;  // encrypt: plaintext in
  logic [127:0] cipher_spi_data_i;        // decrypt: ciphertext in
  logic [127:0] cipher_data_out_o;
  logic         done_o;
  logic         rsp_ready_i;
  logic         tag_match_o;
  logic         aad_valid_i;
  logic         aad_ready_o;
  // Extra working-top ports — tied or left open
  logic         key_consumed_unused;
  logic         key_ready_unused;
  logic         busy_unused;
  logic         err_unused;
  logic         data_out_valid;
  logic         data_out_last_unused;
  logic         page_done_unused;
  logic [4:0]   total_blocks_unused;
  logic [3:0]   state_unused;

  // -------------------------------------------------------------------------
  // DUT — payload length fixed in pkg (PAYLOAD_LEN_BYTES=224 = 14 × 16-byte blocks)
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
    .rsp_valid_o             (done_o),
    .rsp_ready_i             (rsp_ready_i),
    .rsp_auth_ok_o           (tag_match_o),
    .rsp_error_o             (err_unused),
    .data_out_valid_o        (data_out_valid),
    .data_out_ready_i        (1'b1),
    .data_out_last_o         (data_out_last_unused)
  );

  assign key_consumed_unused = start_i && aad_ready_o;
  assign key_ready_unused    = aad_ready_o;
  assign busy_unused         = !aad_ready_o;
  assign page_done_unused    = done_o;
  assign total_blocks_unused = encdec_i ? 5'd16 : 5'd14;
  assign state_unused        = '0;

  initial clk_i = 1'b0;
  always #CLK_HALF clk_i = ~clk_i;

  int pass_count;
  int fail_count;

  // -------------------------------------------------------------------------
  // Test constants
  // -------------------------------------------------------------------------
  localparam logic [127:0] KEY = 128'h000102030405060708090a0b0c0d0e0f;
  localparam logic  [95:0] IV  = 96'hdeadbeef_cafebabe_01234567;
  localparam logic [127:0] AAD = 128'h00000000_00000000_00000000_00abcdef;

  // -------------------------------------------------------------------------
  // Phase storage
  // -------------------------------------------------------------------------
  logic [127:0] P       [14];   // known plaintext: block i = all-bytes (i+1)
  logic [127:0] C       [14];   // ciphertext captured from Phase 1
  logic [127:0] C_tamp  [14];   // tampered copy: C[0] bit 0 flipped
  logic [127:0] P_dec   [14];   // recovered plaintext from Phase 2
  logic [127:0] enc_tag;        // tag from Phase 1 encrypt
  logic [127:0] dec_tag;        // tag produced by Phase 2/3 decrypt run
  logic         phase_match;    // tag_match_o captured at done_o

  // -------------------------------------------------------------------------
  // Tasks
  // -------------------------------------------------------------------------

  task automatic reset_dut;
    rst_ni                  = 1'b0;
    start_i                 = 1'b0;
    encdec_i                = 1'b1;
    key_i                   = '0;
    iv_i                    = '0;
    aad_i                   = '0;
    plen_i                  = '0;
    exp_tag_i               = '0;
    aad_valid_i             = 1'b0;
    data_valid_i            = 1'b0;
    rsp_ready_i             = 1'b0;
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

  // Run one complete GCM operation and capture accepted payload outputs.
  task automatic run_gcm(
    input  logic         is_encrypt,
    input  logic [127:0] blk_in      [14],
    input  logic [127:0] exp_tag_param,
    output logic [127:0] blk_out     [14],
    output logic [127:0] tag_result,
    output logic         match_result
  );
    @(posedge clk_i); #1;
    start_i     = 1'b1;
    encdec_i    = is_encrypt;
    key_i       = KEY;
    iv_i        = IV;
    aad_i       = AAD;
    plen_i      = 8'd224;
    exp_tag_i   = exp_tag_param;
    aad_valid_i = 1'b1;   // assert with start; hold until FSM signals consume-ready
    @(posedge clk_i iff aad_ready_o); #1;
    start_i     = 1'b0;
    aad_valid_i = 1'b0;

    // ST_KEY_INIT -> ST_GEN_H -> ST_PREP_J0 -> ST_ENC_J0 -> ST_PROC_AAD
    while (!data_ready_o) @(posedge clk_i);
    #1;

    fork
      begin : feed_payload
        for (int i = 0; i < 14; i++) begin
          while (!data_ready_o) @(posedge clk_i);
          #1;
          cipher_plaintext_data_i = blk_in[i];
          cipher_spi_data_i       = blk_in[i];
          data_valid_i = 1'b1;
          @(posedge clk_i); #1;
          data_valid_i = 1'b0;
        end
      end

      begin : capture_payload
        int output_idx;
        output_idx = 0;
        while (output_idx < 14) begin
          @(posedge clk_i); #1;
          if (data_out_valid) begin
            blk_out[output_idx] = cipher_data_out_o;
            output_idx++;
          end
        end
      end
    join

    // On encrypt: TAG block (stream word 14) appears after GHASH finalizes.
    // Advance one edge past block 13's valid pulse before waiting for TAG.
    // On decrypt: no TAG in stream; tag_result left as '0.
    if (is_encrypt) begin
      @(posedge clk_i); #1;
      while (!data_out_valid) @(posedge clk_i);
      // Capture the TAG block at the posedge where the while exits (OC_TAG active region).
      // Do NOT add #1 here — the OC transitions OC_TAG→OC_AAD in the same clock's NBA,
      // so a #1 settle would capture the AAD block instead of the tag.
      tag_result = cipher_data_out_o;
    end else
      tag_result = '0;

    wait (done_o); #1;
    rsp_ready_i = 1'b1;
    @(posedge clk_i iff !done_o); #1;
    match_result = tag_match_o;
    rsp_ready_i = 1'b0;
  endtask

  // -------------------------------------------------------------------------
  // Stimulus
  // -------------------------------------------------------------------------
  initial begin
    pass_count = 0;
    fail_count = 0;
    $display("=== tb_aes_gcm_roundtrip: 14-block encrypt / decrypt / tamper ===");

    // Plaintext: block i is all-bytes (i+1), e.g. P[0]=0x0101…01, P[13]=0x0e0e…0e
    for (int i = 0; i < 14; i++)
      P[i] = {16{8'(i + 1)}};

    // -----------------------------------------------------------------------
    // Phase 1: Encrypt
    // -----------------------------------------------------------------------
    $display("--- Phase 1: Encrypt 14 blocks ---");
    reset_dut();
    run_gcm(1'b1, P, 128'h0, C, enc_tag, phase_match);

    if (enc_tag !== '0) begin
      $display("  PASS  enc_tag non-zero = %h", enc_tag);
      pass_count++;
    end else begin
      $display("  FAIL  enc_tag is all zeros");
      fail_count++;
    end

    // Spot-check: ciphertext must differ from plaintext (CTR mode active)
    if (C[0] !== P[0]) begin
      $display("  PASS  C[0] != P[0] (encryption applied)");
      pass_count++;
    end else begin
      $display("  FAIL  C[0] == P[0] (no encryption)");
      fail_count++;
    end

    // -----------------------------------------------------------------------
    // Phase 2: Decrypt with correct ciphertext and tag
    // -----------------------------------------------------------------------
    $display("--- Phase 2: Decrypt (valid ciphertext + tag) ---");
    reset_dut();
    run_gcm(1'b0, C, enc_tag, P_dec, dec_tag, phase_match);

    // Plaintext recovery — CTR mode symmetric, independent of authentication
    for (int i = 0; i < 14; i++)
      chk_vec($sformatf("P_dec[%0d] == P[%0d]", i, i), P_dec[i], P[i]);

    // Authentication — requires GHASH to process incoming CT during decrypt;
    // fails until the aes_gcm_top GHASH mux is gated by encdec (see file header)
    chk_bit("tag_match_o = 1 (authenticated decrypt)", phase_match, 1'b1);

    // -----------------------------------------------------------------------
    // Phase 3: Decrypt with tampered ciphertext — must reject
    // -----------------------------------------------------------------------
    $display("--- Phase 3: Decrypt (C[0] bit 0 flipped → tamper) ---");
    foreach (C_tamp[i]) C_tamp[i] = C[i];
    C_tamp[0] ^= 128'h1;                     // flip LSB of first CT block

    reset_dut();
    run_gcm(1'b0, C_tamp, enc_tag, P_dec, dec_tag, phase_match);
    chk_bit("tag_match_o = 0 (tamper detected)", phase_match, 1'b0);

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    $display("=== %0d passed, %0d failed ===", pass_count, fail_count);
    if (fail_count == 0) begin
      $display("ALL TESTS PASSED");
    end else begin
      $display("TESTS FAILED");
      $fatal(1, "Roundtrip regression failed");
    end

    $finish;
  end

  // Generous watchdog: 3 runs × (setup ~170 + 14 blocks × ~141 + finalize ~130) cycles
  initial begin
    #5_000_000;
    $display("TIMEOUT — simulation did not finish");
    $finish;
  end

endmodule
