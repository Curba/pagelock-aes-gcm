// AES-GCM output controller: page formatting and response channel.
// Streams the FSM's payload blocks, then (encrypt only) appends TAG and AAD,
// and owns rsp_valid/rsp_error. Widths are parameters; the sequence itself
// does not depend on key size because tag and AAD are one block each.
// Author: Baris. Date: 2026-06-07. Parameterised: 2026-09-18.
module aes_gcm_oc
  import aes_gcm_pkg::*;
  #(
    parameter int unsigned DATA_W = GCM_BLOCK_W,
    parameter int unsigned AAD_W  = GCM_AAD_W,
    parameter int unsigned TAG_W  = GCM_TAG_W
  )
  (
  input  logic              clk_i,
  input  logic              rst_ni,
  // command
  input  logic              cmd_accept_i,
  input  logic              mode_i,        // 1=encrypt, 0=decrypt
  input  logic [AAD_W-1:0]  aad_i,
  // from FSM
  input  logic              done_i,
  input  logic [TAG_W-1:0]  tag_i,
  input  logic              tag_match_i,
  input  logic              err_i,
  input  logic              block_out_valid_i,
  input  logic              last_block_i,
  input  logic [DATA_W-1:0] data_block_i,
  // downstream
  input  logic              data_out_ready_i,
  input  logic              rsp_ready_i,
  // outputs
  output logic [DATA_W-1:0] data_out_o,
  output logic              data_out_valid_o,
  output logic              data_out_last_o,
  output logic              rsp_valid_o,
  output logic              rsp_auth_ok_o,
  output logic              rsp_error_o,
  output logic              oc_idle_o
);

  // Tag and AAD are each emitted as exactly one output beat.
  if (AAD_W != DATA_W) begin : g_chk_aad_w
    $fatal(1, "aes_gcm_oc: AAD_W must equal DATA_W (one output beat)");
  end
  if (TAG_W != DATA_W) begin : g_chk_tag_w
    $fatal(1, "aes_gcm_oc: TAG_W must equal DATA_W (one output beat)");
  end

  typedef enum logic [1:0] {
    OC_IDLE = 2'd0,
    OC_PASS = 2'd1,
    OC_TAG  = 2'd2,
    OC_AAD  = 2'd3
  } oc_state_e;

  oc_state_e oc_state_q;
  logic      rsp_valid_q;
  logic      rsp_error_q;
  logic      rsp_done_q;

  logic transfer_accept_w;
  logic rsp_set_w;

  assign transfer_accept_w = data_out_valid_o && data_out_ready_i;

  // Asserted on the cycle the OC first arms a response for the current command.
  // rsp_done_q prevents err_i or done_i from re-arming after the first firing;
  // the OC_AAD path is self-limiting (OC leaves OC_AAD immediately after transfer).
  assign rsp_set_w = ((err_i || (!mode_i && done_i)) && !rsp_done_q)
                   || (oc_state_q == OC_AAD && transfer_accept_w);

  // ---------------------------------------------------------------------------
  // Output controller state machine
  // ---------------------------------------------------------------------------
  // cmd_accept_i takes priority over err_i: the FSM error flag is sticky and
  // only clears on the same edge that accepts the next command, so without
  // this ordering the command issued right after a watchdog abort (without an
  // intervening reset) would leave the OC parked in OC_IDLE and its output
  // would never be streamed. cmd_accept_i can only fire while the OC is idle
  // and no response is pending, so the override is safe.
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      oc_state_q <= OC_IDLE;
    end else if (cmd_accept_i) begin
      oc_state_q <= OC_PASS;
    end else if (err_i) begin
      oc_state_q <= OC_IDLE;
    end else begin
      unique case (oc_state_q)

        OC_IDLE: ;

        OC_PASS: begin
          if (done_i) begin
            if (mode_i)
              oc_state_q <= OC_TAG;
            else
              oc_state_q <= OC_IDLE;
          end
        end

        OC_TAG: begin
          if (transfer_accept_w)
            oc_state_q <= OC_AAD;
        end

        OC_AAD: begin
          if (transfer_accept_w)
            oc_state_q <= OC_IDLE;
        end

        default: oc_state_q <= OC_IDLE;
      endcase
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)
      rsp_done_q <= 1'b0;
    else if (cmd_accept_i)
      rsp_done_q <= 1'b0;
    else if (done_i || err_i)
      rsp_done_q <= 1'b1;
  end

  // ---------------------------------------------------------------------------
  // Output mux: single case block drives data_out_o/valid/last
  // ---------------------------------------------------------------------------
  always_comb begin
    unique case (oc_state_q)

      OC_IDLE: begin
        data_out_o       = '0;
        data_out_valid_o = 1'b0;
        data_out_last_o  = 1'b0;
      end

      OC_PASS: begin
        data_out_o       = data_block_i;
        data_out_valid_o = block_out_valid_i;
        data_out_last_o  = !mode_i && last_block_i;
      end

      OC_TAG: begin
        data_out_o       = tag_i;
        data_out_valid_o = 1'b1;
        data_out_last_o  = 1'b0;
      end

      OC_AAD: begin
        data_out_o       = aad_i;
        data_out_valid_o = 1'b1;
        data_out_last_o  = 1'b1;
      end

      default: begin
        data_out_o       = '0;
        data_out_valid_o = 1'b0;
        data_out_last_o  = 1'b0;
      end
    endcase
  end

  // ---------------------------------------------------------------------------
  // Response channel
  // ---------------------------------------------------------------------------
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)
      rsp_valid_q <= 1'b0;
    else if (rsp_valid_q && rsp_ready_i)
      rsp_valid_q <= 1'b0;
    else if (rsp_set_w)
      rsp_valid_q <= 1'b1;
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)
      rsp_error_q <= 1'b0;
    else if (cmd_accept_i)
      rsp_error_q <= 1'b0;
    else if (err_i)
      rsp_error_q <= 1'b1;
  end

  assign rsp_valid_o   = rsp_valid_q;
  assign rsp_error_o   = rsp_error_q;
  assign rsp_auth_ok_o = mode_i ? 1'b1 : tag_match_i;
  assign oc_idle_o     = (oc_state_q == OC_IDLE);

endmodule
