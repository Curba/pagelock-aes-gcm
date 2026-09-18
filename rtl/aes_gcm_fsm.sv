// AES-GCM control FSM. Sequences key expansion, H derivation, J0 encryption,
// AAD, the NBLOCKS payload blocks and tag finalisation for one command.
// Crypto sequence is unchanged from the proven AES-128 block; the payload
// block count, key width and watchdog threshold are now parameters.
// Author: Baris. Date: 2026-05-04. Parameterised: 2026-09-18.
module aes_gcm_fsm
  import aes_gcm_pkg::*;
  #(
    parameter int unsigned KEY_W       = 128,           // 128 or 256
    parameter int unsigned IV_W        = GCM_IV_W,      // must be 96
    parameter int unsigned AAD_W       = GCM_AAD_W,     // must be 128
    parameter int unsigned TAG_W       = GCM_TAG_W,     // must be 128
    parameter int unsigned DATA_W      = GCM_BLOCK_W,   // must be 128
    parameter int unsigned NBLOCKS     = 14,            // payload blocks per command, >= 1
    parameter int unsigned WDT_TIMEOUT = gcm_wdt_timeout_default(KEY_W)
  )
  (
    input  logic              clk_i,
    input  logic              rst_ni,

    // External control
    input  logic              start_i,
    input  logic              encdec_i,         // 1 = encrypt, 0 = decrypt
    input  logic [KEY_W-1:0]  key_i,
    input  logic [IV_W-1:0]   iv_i,
    input  logic [AAD_W-1:0]  aad_i,
    input  logic              aad_valid_i,
    output logic              aad_ready_o,

    input  logic [TAG_W-1:0]  exp_tag_i,        // decrypt: expected tag

    // Payload block handshake
    input  logic              data_valid_i,
    output logic              data_ready_o,
    input  logic              data_out_ready_i,  // Backpressure from output consumer

    // Status
    output logic              done_o,
    output logic              tag_match_o,

    // Outputs
    output logic [TAG_W-1:0]  tag_o,
    output logic [KEY_W-1:0]  aes_key_o,

    // Secworks AES core
    input  logic              aes_ready_i,
    input  logic              aes_valid_i,
    input  logic [DATA_W-1:0] aes_result_i,

    output logic              aes_init_o,
    output logic              aes_next_o,
    output logic [DATA_W-1:0] aes_block_o,

    // GHASH interface
    output logic              ghash_init_o,       // 1-cycle pulse: load hash, clear accumulator
    output logic              ghash_valid_o,
    output logic              ghash_sel_ct_o,     // 1 = route payload ciphertext into GHASH
    output logic [DATA_W-1:0] ghash_hash_o,
    output logic [DATA_W-1:0] ghash_fsm_data_o,
    input  logic              ghash_ready_i,
    input  logic [DATA_W-1:0] ghash_result_i,

    // Data output strobes
    output logic              block_out_valid_o, // held HIGH while AES result ready; drops after downstream accepts
    output logic              last_block_o,      // Asserted with block_out_valid_o at final block

    // Key handshake
    output logic              key_consumed_o,    // 1-cycle pulse when key expansion completes

    // Error / status
    output logic              fsm_err_o,         // Watchdog timeout or illegal state
    output logic              busy_o
    );

    // -------------------------------------------------------------------------
    // Elaboration-time configuration checks
    // -------------------------------------------------------------------------
    if (!gcm_key_w_supported(KEY_W)) begin : g_chk_key_w
      $fatal(1, "aes_gcm_fsm: KEY_W must be 128 or 256");
    end
    if (IV_W != GCM_IV_W) begin : g_chk_iv_w
      $fatal(1, "aes_gcm_fsm: only IV_W=96 is implemented");
    end
    if (AAD_W != GCM_AAD_W) begin : g_chk_aad_w
      $fatal(1, "aes_gcm_fsm: AAD_W must be 128 (one GHASH block)");
    end
    if (TAG_W != GCM_TAG_W) begin : g_chk_tag_w
      $fatal(1, "aes_gcm_fsm: TAG_W must be 128");
    end
    if (DATA_W != GCM_BLOCK_W) begin : g_chk_data_w
      $fatal(1, "aes_gcm_fsm: DATA_W must be 128 (AES block)");
    end
    if (NBLOCKS < 1) begin : g_chk_nblocks_min
      $fatal(1, "aes_gcm_fsm: NBLOCKS must be at least 1");
    end
    // GCM (SP 800-38D 5.2.1.1) limits the payload to 2^32 - 2 blocks per IV.
    if (NBLOCKS > 32'hFFFF_FFFE - 32'd1) begin : g_chk_nblocks_max
      $fatal(1, "aes_gcm_fsm: NBLOCKS exceeds the GCM counter limit (2^32 - 2)");
    end
    if (WDT_TIMEOUT < 1) begin : g_chk_wdt
      $fatal(1, "aes_gcm_fsm: WDT_TIMEOUT must be at least 1");
    end

    localparam int unsigned BLK_W = $clog2(NBLOCKS + 1);
    localparam int unsigned WDT_W = $clog2(WDT_TIMEOUT + 1);

    // NIST SP 800-38D 6.4: final GHASH input encodes {len(A), len(C)} in bits.
    localparam logic [127:0] LEN_BLOCK = {
        64'(AAD_W),                // len(A) in bits
        64'(NBLOCKS) * 64'(DATA_W) // len(C) in bits
    };

    gcm_fsm_state_t state_q;

    logic [KEY_W-1:0]   reg_key_q;
    logic [IV_W-1:0]    reg_iv_q;
    logic               reg_encdec_q;

    logic [DATA_W-1:0]  reg_hash_q;   // H = AES(K, 0^128), GHASH subkey
    logic [DATA_W-1:0]  reg_EJ0_q;    // EJ0 = AES(K, J0), XORed with final GHASH for tag
    logic [TAG_W-1:0]   reg_tag_q;    // Tag, held until next start_i
    logic               reg_tag_match_q;
    logic [DATA_W-1:0]  reg_ghash_data_q;

    logic               reg_done_q;
    logic [31:0]        reg_ctr_q;    // CTR block index; payload starts at 2
    logic [BLK_W-1:0]   reg_blk_q;    // payload blocks completed

    logic               reg_err_q;    // Error sticks until reset or next start
    logic [WDT_W-1:0]   watchdog_ctr_q; // Anti-stall

    // Counter must never exceed NBLOCKS+1; wrap at 2^32 would break GCM security.
    always_comb if (rst_ni) assert (reg_ctr_q <= 32'(NBLOCKS + 2)) else $error("reg_ctr_q overrun");

    // -------------------------------------------------------------------------
    // Fixed Assignments
    // -------------------------------------------------------------------------
    assign busy_o           = (state_q != ST_IDLE);
    assign done_o           = reg_done_q;
    assign tag_o            = reg_tag_q;
    assign tag_match_o      = reg_tag_match_q;
    assign aes_key_o        = reg_key_q;
    assign fsm_err_o        = reg_err_q;
    assign ghash_fsm_data_o = reg_ghash_data_q;

    // Per-state one-shot flags: prevent outputs from re-firing while the FSM waits in a state
    logic  key_init_sent_q;    // ST_KEY_INIT:     set after aes_init_o pulse
    logic  gen_h_sent_q;       // ST_GEN_H:        set after aes_next_o for zero block
    logic  enc_j0_sent_q;      // ST_ENC_J0:       set after aes_next_o for J0 block
    logic  aad_sent_q;         // ST_PROC_AAD:     set after ghash_valid_o for AAD block
    logic  fin_sent_q;         // ST_FINALIZE:     set after ghash_valid_o for len block
    logic  pl_aes_sent_q;      // ST_PROC_PAYLOAD: set after aes_next_o per block
    logic  pl_ghash_sent_q;    // ST_PROC_PAYLOAD: set after ghash_valid_o per block

    // -------------------------------------------------------------------------
    // Sequential
    // -------------------------------------------------------------------------
    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) begin
        state_q           <= ST_IDLE;
        reg_err_q         <= 1'b0;
        watchdog_ctr_q    <= '0;
        reg_tag_match_q   <= 1'b0;
        reg_ghash_data_q  <= '0;
        reg_key_q         <= '0;
        reg_iv_q          <= '0;
        reg_encdec_q      <= 1'b0;
        reg_hash_q        <= '0;
        reg_EJ0_q         <= '0;
        reg_tag_q         <= '0;
        reg_done_q        <= 1'b0;
        reg_ctr_q         <= 32'd2;
        reg_blk_q         <= '0;
        key_init_sent_q   <= 1'b0;
        gen_h_sent_q      <= 1'b0;
        enc_j0_sent_q     <= 1'b0;
        aad_sent_q        <= 1'b0;
        fin_sent_q        <= 1'b0;
        pl_aes_sent_q     <= 1'b0;
        pl_ghash_sent_q   <= 1'b0;
      end else begin
        // Watchdog: cleared in idle and on every accepted payload block,
        // counts in every other state.
        if (state_q == ST_IDLE ||
           (state_q == ST_PROC_PAYLOAD && data_valid_i && aes_ready_i && !pl_aes_sent_q)) begin
            watchdog_ctr_q <= '0;
        end else if (state_q == ST_KEY_INIT || state_q == ST_GEN_H || state_q == ST_PREP_J0 ||
                     state_q == ST_ENC_J0 || state_q == ST_PROC_AAD ||
                     state_q == ST_PROC_PAYLOAD || state_q == ST_FINALIZE) begin
            watchdog_ctr_q <= watchdog_ctr_q + WDT_W'(1);
        end

        // Fault / Timeout Trigger
        if (watchdog_ctr_q == WDT_W'(WDT_TIMEOUT)) begin
            state_q   <= ST_IDLE;
            reg_err_q <= 1'b1;
        end else begin
          unique case (state_q)
            ST_IDLE: begin
              if (start_i) begin
                reg_key_q       <= key_i;
                reg_iv_q        <= iv_i;
                reg_encdec_q    <= encdec_i;
                reg_done_q      <= 1'b0;
                reg_err_q       <= 1'b0;
                reg_tag_match_q <= 1'b0;
                key_init_sent_q <= 1'b0;
                aad_sent_q      <= 1'b0;
                gen_h_sent_q    <= 1'b0;
                enc_j0_sent_q   <= 1'b0;
                pl_aes_sent_q   <= 1'b0;
                pl_ghash_sent_q <= 1'b0;
                fin_sent_q      <= 1'b0;
                state_q         <= ST_KEY_INIT;
              end
            end

            ST_KEY_INIT: begin
              key_init_sent_q <= 1'b1;
              if (key_init_sent_q && aes_ready_i) begin
                key_init_sent_q <= 1'b0;
                reg_key_q       <= '0; // Key zeroisation after expansion
                state_q         <= ST_GEN_H;
              end
            end

            ST_GEN_H: begin
              if (!gen_h_sent_q && aes_ready_i)
                gen_h_sent_q <= 1'b1;
              if (aes_valid_i) begin
                reg_hash_q   <= aes_result_i;
                gen_h_sent_q <= 1'b0;
                state_q      <= ST_PREP_J0;
              end
            end

            ST_PREP_J0: begin
              state_q <= ST_ENC_J0;       // one cycle: ghash_init_o fires combinationally
            end

            ST_ENC_J0: begin
              if (!enc_j0_sent_q && aes_ready_i)
                enc_j0_sent_q <= 1'b1;
              // aad_ready_o is consumer-driven (enc_j0_sent_q && aes_valid_i);
              // the top pre-latches AAD so aad_valid_i is constant high.
              if (enc_j0_sent_q && aes_valid_i && aad_valid_i) begin
                reg_ghash_data_q <= aad_i;
                reg_EJ0_q        <= aes_result_i;
                enc_j0_sent_q    <= 1'b0;
                state_q          <= ST_PROC_AAD;
              end
            end

            // GHASH ready_o is HIGH the same cycle valid_i fires, LOW the next.
            // The nested-if exits on the 2nd ready pulse after the flag is set.
            ST_PROC_AAD: begin
              if (ghash_ready_i) begin
                aad_sent_q <= 1'b1;
                if (aad_sent_q) begin
                  reg_ctr_q <= 32'd2;
                  reg_blk_q <= '0;
                  state_q   <= ST_PROC_PAYLOAD;
                end
              end
            end

            ST_PROC_PAYLOAD: begin
              // Phase 1: accept block, fire AES CTR request; ctr must stay stable through CTRL_INIT
              if (!pl_aes_sent_q && data_valid_i && aes_ready_i)
                pl_aes_sent_q <= 1'b1;
              // Phase 2: AES done, output accepted: feed ciphertext to GHASH
              if (pl_aes_sent_q && !pl_ghash_sent_q && aes_valid_i && data_out_ready_i && ghash_ready_i)
                pl_ghash_sent_q <= 1'b1;
              // Phase 3: GHASH done: advance counter, next block or finalise
              if (pl_ghash_sent_q && ghash_ready_i) begin
                pl_aes_sent_q   <= 1'b0;
                pl_ghash_sent_q <= 1'b0;
                reg_ctr_q       <= reg_ctr_q + 32'd1;
                reg_blk_q       <= reg_blk_q + BLK_W'(1);
                if (reg_blk_q == BLK_W'(NBLOCKS - 1)) begin
                  reg_ghash_data_q <= LEN_BLOCK;
                  state_q          <= ST_FINALIZE;
                end
              end
            end

            ST_FINALIZE: begin
              if (ghash_ready_i) begin
                fin_sent_q <= 1'b1;
                if (fin_sent_q) begin
                  reg_tag_q       <= ghash_result_i ^ reg_EJ0_q;
                  reg_tag_match_q <= !reg_encdec_q && ((ghash_result_i ^ reg_EJ0_q) == exp_tag_i);
                  reg_done_q      <= 1'b1;
                  fin_sent_q      <= 1'b0;
                  state_q         <= ST_IDLE;
                end
              end
            end

            default: begin
              state_q   <= ST_IDLE;
              reg_err_q <= 1'b1;
            end
        endcase
      end
    end
  end

    // -------------------------------------------------------------------------
    // Combinational outputs
    // -------------------------------------------------------------------------
    always_comb begin
      data_ready_o      = 1'b0;
      aad_ready_o       = 1'b0;
      aes_init_o        = 1'b0;
      aes_next_o        = 1'b0;
      aes_block_o       = '0;
      ghash_init_o      = 1'b0;
      ghash_valid_o     = 1'b0;
      ghash_sel_ct_o    = 1'b0;
      ghash_hash_o      = reg_hash_q;
      block_out_valid_o = 1'b0;
      last_block_o      = 1'b0;
      key_consumed_o    = 1'b0;

      // One-cycle pulse on the cycle the FSM exits ST_KEY_INIT.
      if (state_q == ST_KEY_INIT)
        key_consumed_o = key_init_sent_q && aes_ready_i;

      // Asserted only on the exact cycle the FSM consumes AAD (J0 result available).
      aad_ready_o = (state_q == ST_ENC_J0) && enc_j0_sent_q && aes_valid_i;

      unique case (state_q)

        ST_IDLE: ;

        ST_KEY_INIT: begin
          aes_init_o = !key_init_sent_q;
        end

        ST_GEN_H: begin
            aes_next_o = !gen_h_sent_q && aes_ready_i;
            // aes_block_o = '0 -> H = AES(K, 0^128)
        end

        ST_PREP_J0: begin
            ghash_init_o = 1'b1;
        end

        ST_ENC_J0: begin
            aes_next_o  = !enc_j0_sent_q && aes_ready_i;
            aes_block_o = {reg_iv_q, 32'h0000_0001};
        end

        ST_PROC_AAD: begin
            ghash_valid_o = !aad_sent_q && ghash_ready_i;
        end

        ST_PROC_PAYLOAD: begin
            data_ready_o      = !pl_aes_sent_q && aes_ready_i;
            aes_next_o        = !pl_aes_sent_q && data_valid_i && aes_ready_i;
            aes_block_o       = {reg_iv_q, reg_ctr_q};
            ghash_sel_ct_o    = 1'b1;
            // block_out_valid_o is independent of data_out_ready_i (valid must not
            // depend on ready). GHASH feed is gated on downstream acceptance so
            // GHASH and the output consumer receive the same CT block atomically.
            block_out_valid_o = pl_aes_sent_q && !pl_ghash_sent_q && aes_valid_i && ghash_ready_i;
            ghash_valid_o     = block_out_valid_o && data_out_ready_i;
            last_block_o      = block_out_valid_o && (reg_blk_q == BLK_W'(NBLOCKS - 1));
        end

        ST_FINALIZE: begin
            ghash_valid_o = !fin_sent_q && ghash_ready_i;
        end

        default: ;

      endcase
    end

endmodule
