// AES-GCM GHASH: bit-serial GF(2^128) multiply-accumulate over 128-bit blocks.
// Width is fixed by the algorithm; the module takes no user parameters.
// Author: Baris. Date: 2026-05-05. Parameter-free port list: 2026-09-18.
module aes_ghash
  import aes_gcm_pkg::*;
  (
    input  logic                    clk_i,
    input  logic                    rst_ni,

    input  logic                    init_i,
    input  logic [GCM_BLOCK_W-1:0]  hash_i,

    input  logic                    valid_i,
    input  logic [GCM_BLOCK_W-1:0]  data_i,   // CT or AAD
    output logic                    ready_o,

    output logic [GCM_BLOCK_W-1:0]  result_o
  );

  // The irreducible polynomial x^128 + x^7 + x^2 + x + 1.
  localparam logic [127:0] GCM_R = 128'hE100_0000_0000_0000_0000_0000_0000_0000;

  ghash_state_e state_q;

  // The multiplication key: loaded from hash_i on init, reused for every block.
  logic [127:0] hash_key_q;
  // The running result: cleared on init, updated after each block completes.
  logic [127:0] ghash_acc_q;
  // The current block XORed with the running result. Loaded when a new block
  // arrives and held for all 128 multiply cycles.
  logic [127:0] xor_input_q;
  // Starts as the multiplication key, shifted right by one bit each cycle.
  // If the dropped bit was 1, a correction constant is XORed in to keep
  // the value within the field.
  logic [127:0] gf_multiplier_q;
  // Builds up the final result one bit at a time. Each cycle, if the current
  // bit of xor_input_q is 1, gf_multiplier_q is folded in. Otherwise unchanged.
  logic [127:0] partial_product_q;
  // Bit index counting from 127 down to 0; one GF step per cycle.
  logic [6:0]   bit_idx_q;

  // ---------------------------------------------------------------------------
  // Behavior summary:
  //   init_i  (any cycle in ST_GH_IDLE): load hash_i into hash_key_q, clear
  //           ghash_acc_q to 0.
  //   valid_i (any cycle in ST_GH_IDLE): latch the current block XORed with
  //           the running result, then start the 128-cycle multiply.
  //   when init_i and valid_i arrive on the same cycle the running result is
  //   treated as 0 and hash is read from the input port directly because
  //   hash_key_q has not been written yet.
  // ---------------------------------------------------------------------------
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      state_q           <= ST_GH_IDLE;
      hash_key_q        <= '0;
      ghash_acc_q       <= '0;
      xor_input_q       <= '0;
      gf_multiplier_q   <= '0;
      partial_product_q <= '0;
      bit_idx_q         <= '0;
    end
    else begin
      unique case (state_q)

      ST_GH_IDLE: begin
        if (init_i) begin
          hash_key_q  <= hash_i;
          ghash_acc_q <= '0;
        end

        if (valid_i) begin
          xor_input_q       <= (init_i ? 128'h0 : ghash_acc_q) ^ data_i;
          gf_multiplier_q   <= init_i ? hash_i : hash_key_q;
          partial_product_q <= '0;
          bit_idx_q         <= 7'd127;
          state_q           <= ST_GH_BUSY;
        end
      end

      ST_GH_BUSY: begin
        if (bit_idx_q == 7'd0) begin
          // Final iteration: fold the last term straight into the running
          // result. The result is valid the same cycle ready_o returns high.
          ghash_acc_q <= xor_input_q[0] ? (partial_product_q ^ gf_multiplier_q) : partial_product_q;
          state_q     <= ST_GH_IDLE;
        end else begin
          partial_product_q <= xor_input_q[bit_idx_q] ? (partial_product_q ^ gf_multiplier_q) : partial_product_q;
          gf_multiplier_q   <= gf_multiplier_q[0] ? ((gf_multiplier_q >> 1) ^ GCM_R) : (gf_multiplier_q >> 1);
          bit_idx_q         <= bit_idx_q - 7'd1;
        end
      end

      default: state_q <= ST_GH_IDLE;
    endcase
  end
end

  // ready_o is high on the same cycle valid_i fires (state_q is still idle)
  // and drops one cycle later when state_q becomes ST_GH_BUSY.
  assign ready_o  = (state_q == ST_GH_IDLE);
  assign result_o = ghash_acc_q;

endmodule
