// AES-GCM top-level wrapper (standalone, parameterised).
//
// Configuration knobs:
//   KEY_W       128 or 256. Selects the AES key schedule and the key port width.
//   PAGE_BYTES  Total page size in bytes including the 32-byte TAG+AAD trailer.
//               Payload blocks per command = (PAGE_BYTES - 32) / 16.
//   WDT_TIMEOUT Watchdog threshold in cycles (default from aes_gcm_pkg).
//   IV_W/AAD_W/TAG_W/DATA_W are fixed by GCM and only exist so integrators can
//   read them back; any non-default value is rejected at elaboration.
//
// Every illegal combination fails at elaboration with a $fatal message, so an
// unsupported geometry can never be synthesised or simulated silently.
//
// Naming: _q register, _w wire, _i input port, _o output port.
// Author: Baris. Date: 2026-05-02. Parameterised: 2026-09-18.
module aes_gcm_top
    import aes_gcm_pkg::*;
    #(
        parameter int unsigned KEY_W       = 128,
        parameter int unsigned PAGE_BYTES  = 256,
        parameter int unsigned IV_W        = GCM_IV_W,
        parameter int unsigned AAD_W       = GCM_AAD_W,
        parameter int unsigned TAG_W       = GCM_TAG_W,
        parameter int unsigned DATA_W      = GCM_BLOCK_W,
        parameter int unsigned WDT_TIMEOUT = gcm_wdt_timeout_default(KEY_W),
        // Derived geometry (read-only, cannot be overridden). ENC/DEC_OUT_BLOCKS
        // are informational for integrators and testbenches.
        localparam int unsigned META_BYTES     = (TAG_W + AAD_W) / 8,
        localparam int unsigned PAYLOAD_BYTES  = PAGE_BYTES - META_BYTES,
        localparam int unsigned NBLOCKS        = PAYLOAD_BYTES / (DATA_W / 8),
        /* verilator lint_off UNUSEDPARAM */
        localparam int unsigned ENC_OUT_BLOCKS = NBLOCKS + 2,
        localparam int unsigned DEC_OUT_BLOCKS = NBLOCKS
        /* verilator lint_on UNUSEDPARAM */
    )
    (
        input  logic                clk_i,
        input  logic                rst_ni,

        // Command channel
        input  logic                cmd_valid_i,
        output logic                cmd_ready_o,
        input  logic                cmd_mode_i,       // 1 = encrypt, 0 = decrypt
        input  logic [KEY_W-1:0]    cmd_key_i,
        input  logic [IV_W-1:0]     cmd_iv_i,
        input  logic [AAD_W-1:0]    cmd_aad_i,
        input  logic [TAG_W-1:0]    cmd_exp_tag_i,

        // Data input stream
        input  logic                data_in_valid_i,
        output logic                data_in_ready_o,
        input  logic [DATA_W-1:0]   data_in_i,

        // Data output stream
        output logic [DATA_W-1:0]   data_out_o,
        output logic                data_out_valid_o,
        input  logic                data_out_ready_i,
        output logic                data_out_last_o,

        // Response channel
        output logic                rsp_valid_o,
        input  logic                rsp_ready_i,
        output logic                rsp_auth_ok_o,
        output logic                rsp_error_o
    );

    // ---------------------------------------------------------------------------
    // Elaboration-time configuration checks (the single source of truth for
    // what is a legal configuration; see docs/parameters.md)
    // ---------------------------------------------------------------------------
    if (!gcm_key_w_supported(KEY_W)) begin : g_chk_key_w
      $fatal(1, "aes_gcm_top: KEY_W must be 128 or 256");
    end
    if (DATA_W != GCM_BLOCK_W) begin : g_chk_data_w
      $fatal(1, "aes_gcm_top: DATA_W must be 128 (AES block width)");
    end
    if (IV_W != GCM_IV_W) begin : g_chk_iv_w
      $fatal(1, "aes_gcm_top: only the 96-bit IV construction is implemented (IV_W must be 96)");
    end
    if (AAD_W != GCM_AAD_W) begin : g_chk_aad_w
      $fatal(1, "aes_gcm_top: AAD_W is fixed at 128 bits (one block) for every key size");
    end
    if (TAG_W != GCM_TAG_W) begin : g_chk_tag_w
      $fatal(1, "aes_gcm_top: TAG_W is fixed at 128 bits");
    end
    if (PAGE_BYTES % (DATA_W / 8) != 0) begin : g_chk_page_align
      $fatal(1, "aes_gcm_top: PAGE_BYTES must be a multiple of 16");
    end
    if (PAGE_BYTES < META_BYTES + DATA_W / 8) begin : g_chk_page_min
      $fatal(1, "aes_gcm_top: PAGE_BYTES must be at least 48 (TAG + AAD + one payload block)");
    end
    if (WDT_TIMEOUT < 1) begin : g_chk_wdt
      $fatal(1, "aes_gcm_top: WDT_TIMEOUT must be at least 1");
    end

    // ---------------------------------------------------------------------------
    // Internal wires: FSM outputs
    // ---------------------------------------------------------------------------
    logic              busy_w;
    logic              done_w;
    logic              tag_match_w;
    logic [TAG_W-1:0]  tag_w;
    logic              block_out_valid_w;
    logic              last_block_w;
    logic              err_w;
    /* verilator lint_off UNUSEDSIGNAL */
    logic              aad_ready_unused_w;     // FSM AAD handshake, AAD is pre-latched
    logic              key_consumed_unused_w;  // FSM key pulse, not exposed at this level
    /* verilator lint_on UNUSEDSIGNAL */

    // ---------------------------------------------------------------------------
    // Command accept and ready
    // ---------------------------------------------------------------------------
    logic              cmd_accept_w;
    logic              oc_idle_w;
    logic              oc_rsp_valid_w;
    logic              oc_rsp_auth_ok_w;
    logic              oc_rsp_error_w;
    logic              oc_rsp_ready_w;
    logic              reg_mode_q;
    logic              rsp_pending_q;

    assign cmd_accept_w   = cmd_valid_i && cmd_ready_o;
    assign cmd_ready_o    = !busy_w && oc_idle_w && !rsp_pending_q
                            && !oc_rsp_valid_w;
    assign rsp_valid_o    = oc_rsp_valid_w;
    // Decrypt: the response is only released once tag finalisation is done
    // (or an error is flagged), even if the consumer is already ready.
    assign oc_rsp_ready_w = rsp_ready_i && (reg_mode_q || done_w || oc_rsp_error_w);
    assign rsp_auth_ok_o  = oc_rsp_auth_ok_w;
    assign rsp_error_o    = oc_rsp_error_w;

    // ---------------------------------------------------------------------------
    // AES core bus
    // ---------------------------------------------------------------------------
    logic [KEY_W-1:0]  aes_fsm_key_w;
    logic [255:0]      aes_core_key_w;     // Secworks core always takes 256 bits
    logic [DATA_W-1:0] ciphertext_w;
    logic              aes_init_w;
    logic              aes_next_w;
    logic [DATA_W-1:0] aes_block_w;
    logic              aes_ready_w;
    logic              aes_valid_w;
    logic [DATA_W-1:0] aes_result_w;
    logic [DATA_W-1:0] reg_ciphertext_q;

    // Secworks keylen: 0 = AES-128 (key in the upper 128 bits), 1 = AES-256.
    localparam logic AES_KEYLEN = (KEY_W == 256);

    if (KEY_W == 256) begin : g_key_256
      assign aes_core_key_w = aes_fsm_key_w;
    end else begin : g_key_128
      assign aes_core_key_w = {aes_fsm_key_w, 128'd0};
    end

    // ---------------------------------------------------------------------------
    // GHASH bus
    // ---------------------------------------------------------------------------
    logic              ghash_init_w;
    logic              ghash_valid_w;
    logic              ghash_sel_ct_w;
    logic [DATA_W-1:0] ghash_hash_w;
    logic [DATA_W-1:0] ghash_fsm_data_w;
    logic [DATA_W-1:0] ghash_data_w;
    logic              ghash_ready_w;
    logic [DATA_W-1:0] ghash_result_w;

    // ---------------------------------------------------------------------------
    // Command latch registers (key and IV are latched inside the FSM so the
    // key can be zeroised there after expansion)
    // ---------------------------------------------------------------------------
    logic [AAD_W-1:0]  reg_aad_q;
    logic [TAG_W-1:0]  reg_exp_tag_q;

    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) begin
        reg_mode_q    <= 1'b0;
        reg_aad_q     <= '0;
        reg_exp_tag_q <= '0;
      end else if (cmd_accept_w) begin
        reg_mode_q    <= cmd_mode_i;
        reg_aad_q     <= cmd_aad_i;
        reg_exp_tag_q <= cmd_exp_tag_i;
      end
    end

    // Response pending: gates cmd_ready_o until the consumer acknowledges
    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni)
        rsp_pending_q <= 1'b0;
      else if (rsp_valid_o && rsp_ready_i)
        rsp_pending_q <= 1'b0;
      else if (rsp_valid_o)
        rsp_pending_q <= 1'b1;
    end

    // ---------------------------------------------------------------------------
    // Datapath: CTR keystream XOR, GHASH source select
    // ---------------------------------------------------------------------------
    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni)
        reg_ciphertext_q <= '0;
      else if (data_in_valid_i && data_in_ready_o)
        reg_ciphertext_q <= data_in_i;
    end

    assign ciphertext_w = aes_result_w ^ reg_ciphertext_q;

    // GHASH always authenticates ciphertext:
    //   encrypt -> freshly computed ciphertext_w
    //   decrypt -> raw incoming ciphertext (reg_ciphertext_q)
    assign ghash_data_w = ghash_sel_ct_w ? (reg_mode_q ? ciphertext_w : reg_ciphertext_q) : ghash_fsm_data_w;

    // ---------------------------------------------------------------------------
    // AES core (Secworks, vendored, read-only)
    // ---------------------------------------------------------------------------
    aes_core u_aes_core (
      .clk            (clk_i),
      .reset_n        (rst_ni),
      .encdec         (1'b1),            // CTR mode: forward cipher in both directions
      .init           (aes_init_w),
      .next           (aes_next_w),
      .ready          (aes_ready_w),
      .key            (aes_core_key_w),
      .keylen         (AES_KEYLEN),
      .block          (aes_block_w),
      .result         (aes_result_w),
      .result_valid   (aes_valid_w)
    );

    // ---------------------------------------------------------------------------
    // GCM FSM
    // ---------------------------------------------------------------------------
    aes_gcm_fsm #(
      .KEY_W       (KEY_W),
      .IV_W        (IV_W),
      .AAD_W       (AAD_W),
      .TAG_W       (TAG_W),
      .DATA_W      (DATA_W),
      .NBLOCKS     (NBLOCKS),
      .WDT_TIMEOUT (WDT_TIMEOUT)
    ) u_aes_fsm (
      .clk_i              (clk_i),
      .rst_ni             (rst_ni),
      .start_i            (cmd_accept_w),
      .encdec_i           (cmd_mode_i),
      .key_i              (cmd_key_i),
      .iv_i               (cmd_iv_i),
      .aad_i              (reg_aad_q),
      .aad_valid_i        (1'b1),
      .aad_ready_o        (aad_ready_unused_w),   // AAD is pre-latched in top
      .exp_tag_i          (reg_exp_tag_q),
      .data_valid_i       (data_in_valid_i),
      .data_ready_o       (data_in_ready_o),
      .data_out_ready_i   (data_out_ready_i),
      .done_o             (done_w),
      .tag_match_o        (tag_match_w),
      .tag_o              (tag_w),
      .aes_key_o          (aes_fsm_key_w),
      .aes_ready_i        (aes_ready_w),
      .aes_valid_i        (aes_valid_w),
      .aes_result_i       (aes_result_w),
      .aes_init_o         (aes_init_w),
      .aes_next_o         (aes_next_w),
      .aes_block_o        (aes_block_w),
      .ghash_init_o       (ghash_init_w),
      .ghash_valid_o      (ghash_valid_w),
      .ghash_sel_ct_o     (ghash_sel_ct_w),
      .ghash_hash_o       (ghash_hash_w),
      .ghash_fsm_data_o   (ghash_fsm_data_w),
      .ghash_ready_i      (ghash_ready_w),
      .ghash_result_i     (ghash_result_w),
      .block_out_valid_o  (block_out_valid_w),
      .last_block_o       (last_block_w),
      .key_consumed_o     (key_consumed_unused_w), // key lifetime is implicit in the cmd handshake
      .fsm_err_o          (err_w),
      .busy_o             (busy_w)
    );

    // ---------------------------------------------------------------------------
    // Output controller
    // ---------------------------------------------------------------------------
    aes_gcm_oc #(
      .DATA_W (DATA_W),
      .AAD_W  (AAD_W),
      .TAG_W  (TAG_W)
    ) u_aes_oc (
      .clk_i              (clk_i),
      .rst_ni             (rst_ni),
      .cmd_accept_i       (cmd_accept_w),
      .mode_i             (reg_mode_q),
      .aad_i              (reg_aad_q),
      .done_i             (done_w),
      .tag_i              (tag_w),
      .tag_match_i        (tag_match_w),
      .err_i              (err_w),
      .block_out_valid_i  (block_out_valid_w),
      .last_block_i       (last_block_w),
      .data_block_i       (ciphertext_w),
      .data_out_ready_i   (data_out_ready_i),
      .rsp_ready_i        (oc_rsp_ready_w),
      .data_out_o         (data_out_o),
      .data_out_valid_o   (data_out_valid_o),
      .data_out_last_o    (data_out_last_o),
      .rsp_valid_o        (oc_rsp_valid_w),
      .rsp_auth_ok_o      (oc_rsp_auth_ok_w),
      .rsp_error_o        (oc_rsp_error_w),
      .oc_idle_o          (oc_idle_w)
    );

    // ---------------------------------------------------------------------------
    // GHASH block
    // ---------------------------------------------------------------------------
    aes_ghash u_aes_ghash (
      .clk_i    (clk_i),
      .rst_ni   (rst_ni),
      .init_i   (ghash_init_w),
      .hash_i   (ghash_hash_w),
      .valid_i  (ghash_valid_w),
      .data_i   (ghash_data_w),
      .ready_o  (ghash_ready_w),
      .result_o (ghash_result_w)
    );

endmodule
