// Purpose: Black-box verification of the AES-GCM v2 external contract.
// Author: Codex. Date: 2026-06-09.
`timescale 1ns/1ps

module tb_v2_contract;
  // Default geometry of aes_gcm_top (AES-128, 256-byte page)
  localparam int KEY_W  = 128;
  localparam int IV_W   = 96;
  localparam int TAG_W  = 128;
  localparam int DATA_W = 128;
  localparam int AAD_W  = 128;

  localparam int NBLOCKS = 14;
  localparam int ENC_BLOCKS = 16;

  localparam logic [127:0] KEY =
      128'h2b7e151628aed2a6abf7158809cf4f3c;
  localparam logic [95:0] IV =
      96'hcafebabe_facedbad_decaf888;
  localparam logic [127:0] AAD =
      128'hfeedface_deadbeef_feedface_deadbeef;

  logic clk_i;
  logic rst_ni;

  logic cmd_valid_i;
  logic cmd_ready_o;
  logic cmd_mode_i;
  logic [127:0] cmd_key_i;
  logic [95:0] cmd_iv_i;
  logic [127:0] cmd_aad_i;
  logic [127:0] cmd_exp_tag_i;

  logic data_in_valid_i;
  logic data_in_ready_o;
  logic [127:0] data_in_i;

  logic [127:0] data_out_o;
  logic data_out_valid_o;
  logic data_out_ready_i;
  logic data_out_last_o;

  logic rsp_valid_o;
  logic rsp_ready_i;
  logic rsp_auth_ok_o;
  logic rsp_error_o;

  logic [127:0] plaintext [NBLOCKS];
  logic [127:0] golden_ct [NBLOCKS];
  logic [127:0] tag_file [1];
  logic [127:0] golden_tag;
  logic [127:0] ciphertext [NBLOCKS];
  logic [127:0] recovered [NBLOCKS];
  logic [127:0] tampered [NBLOCKS];

  int pass_count;
  int fail_count;
  longint unsigned cycle_count;

  aes_gcm_top dut (
    .clk_i,
    .rst_ni,
    .cmd_valid_i,
    .cmd_ready_o,
    .cmd_mode_i,
    .cmd_key_i,
    .cmd_iv_i,
    .cmd_aad_i,
    .cmd_exp_tag_i,
    .data_in_valid_i,
    .data_in_ready_o,
    .data_in_i,
    .data_out_o,
    .data_out_valid_o,
    .data_out_ready_i,
    .data_out_last_o,
    .rsp_valid_o,
    .rsp_ready_i,
    .rsp_auth_ok_o,
    .rsp_error_o
  );

  initial clk_i = 1'b0;
  always #5 clk_i = ~clk_i;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni)
      cycle_count <= '0;
    else
      cycle_count <= cycle_count + 1;
  end

  task automatic check(input string name, input logic condition);
    if (condition) begin
      $display("  PASS  %s", name);
      pass_count++;
    end else begin
      $display("  FAIL  %s", name);
      fail_count++;
    end
  endtask

  task automatic reset_dut;
    rst_ni          = 1'b0;
    cmd_valid_i     = 1'b0;
    cmd_mode_i      = 1'b0;
    cmd_key_i       = '0;
    cmd_iv_i        = '0;
    cmd_aad_i       = '0;
    cmd_exp_tag_i   = '0;
    data_in_valid_i = 1'b0;
    data_in_i       = '0;
    data_out_ready_i = 1'b1;
    rsp_ready_i     = 1'b0;
    repeat (4) @(posedge clk_i);
    #1;
    rst_ni = 1'b1;
    @(posedge clk_i);
    #1;
    check("cmd_ready_o is high after reset", cmd_ready_o === 1'b1);
  endtask

  task automatic send_command(
    input logic mode,
    input logic [127:0] expected_tag
  );
    @(negedge clk_i);
    cmd_mode_i    = mode;
    cmd_key_i     = KEY;
    cmd_iv_i      = IV;
    cmd_aad_i     = AAD;
    cmd_exp_tag_i = expected_tag;
    cmd_valid_i   = 1'b1;

    do @(posedge clk_i); while (!cmd_ready_o);
    #1;
    cmd_valid_i   = 1'b0;

    // The contract permits every command field to change after acceptance.
    cmd_mode_i    = ~mode;
    cmd_key_i     = ~KEY;
    cmd_iv_i      = ~IV;
    cmd_aad_i     = ~AAD;
    cmd_exp_tag_i = ~expected_tag;
    check("cmd_ready_o drops after command acceptance",
          cmd_ready_o === 1'b0);
  endtask

  task automatic send_payload(input logic [127:0] blocks [NBLOCKS]);
    for (int i = 0; i < NBLOCKS; i++) begin
      wait (data_in_ready_o);
      @(negedge clk_i);
      data_in_i       = blocks[i];
      data_in_valid_i = 1'b1;
      do @(posedge clk_i); while (!data_in_ready_o);
      #1;
      data_in_valid_i = 1'b0;
      data_in_i       = 'x;
    end
  endtask

  task automatic receive_outputs(
    input int expected_count,
    output logic [127:0] blocks [ENC_BLOCKS],
    output longint unsigned last_transfer_cycle
  );
    logic [127:0] stalled_data;
    logic stalled_last;
    logic stable_while_stalled;

    last_transfer_cycle = '0;
    for (int i = 0; i < expected_count; i++) begin
      wait (data_out_valid_o);

      // Stall every output briefly. Valid, data, and last must remain stable.
      @(negedge clk_i);
      data_out_ready_i = 1'b0;
      stalled_data = data_out_o;
      stalled_last = data_out_last_o;
      stable_while_stalled = 1'b1;
      repeat (3) begin
        @(posedge clk_i);
        #1;
        if (data_out_valid_o !== 1'b1 ||
            data_out_o !== stalled_data ||
            data_out_last_o !== stalled_last)
          stable_while_stalled = 1'b0;
      end
      check($sformatf("output %0d is stable while stalled", i),
            stable_while_stalled);

      @(negedge clk_i);
      data_out_ready_i = 1'b1;
      @(posedge clk_i);
      blocks[i] = data_out_o;
      last_transfer_cycle = cycle_count;
      check($sformatf("last is correct on output %0d", i),
            data_out_last_o === (i == expected_count - 1));
      #1;
    end
  endtask

  task automatic check_response(
    input logic expected_auth,
    input logic expected_error,
    output longint unsigned response_cycle
  );
    logic auth_snapshot;
    logic error_snapshot;
    logic response_held;

    wait (rsp_valid_o);
    response_cycle = cycle_count;
    auth_snapshot = rsp_auth_ok_o;
    error_snapshot = rsp_error_o;

    check("cmd_ready_o stays low while response is pending",
          cmd_ready_o === 1'b0);
    response_held = 1'b1;
    repeat (3) begin
      @(posedge clk_i);
      #1;
      if (rsp_valid_o !== 1'b1 ||
          rsp_auth_ok_o !== auth_snapshot ||
          rsp_error_o !== error_snapshot)
        response_held = 1'b0;
    end
    check("response is held stable until acknowledged", response_held);

    check("rsp_auth_ok_o matches expected result",
          auth_snapshot === expected_auth);
    check("rsp_error_o matches expected result",
          error_snapshot === expected_error);

    rsp_ready_i = 1'b1;
    @(posedge clk_i);
    #1;
    rsp_ready_i = 1'b0;
    check("rsp_valid_o clears after acknowledgment",
          rsp_valid_o === 1'b0);
    check("cmd_ready_o returns after acknowledgment",
          cmd_ready_o === 1'b1);
  endtask

  task automatic test_encrypt;
    logic [127:0] outputs [ENC_BLOCKS];
    longint unsigned last_cycle;
    longint unsigned response_cycle;

    $display("\n--- Contract test: encrypt ---");
    reset_dut();
    send_command(1'b1, '0);

    fork
      send_payload(plaintext);
      receive_outputs(ENC_BLOCKS, outputs, last_cycle);
    join

    for (int i = 0; i < NBLOCKS; i++) begin
      ciphertext[i] = outputs[i];
      check($sformatf("encrypt ciphertext block %0d", i),
            outputs[i] === golden_ct[i]);
    end
    check("encrypt output block 14 is the tag",
          outputs[14] === golden_tag);
    check("encrypt output block 15 is the accepted AAD",
          outputs[15] === AAD);

    check_response(1'b1, 1'b0, response_cycle);
    check("encrypt response follows the final output transfer",
          response_cycle >= last_cycle);
    $display("  INFO  encrypt response latency after final output: %0d cycles",
             response_cycle - last_cycle);
  endtask

  task automatic test_decrypt(
    input logic [127:0] input_blocks [NBLOCKS],
    input logic expected_auth
  );
    logic [127:0] outputs [ENC_BLOCKS];
    longint unsigned last_cycle;
    longint unsigned response_cycle;

    $display("\n--- Contract test: decrypt, auth=%0b ---", expected_auth);
    reset_dut();
    send_command(1'b0, golden_tag);

    fork
      send_payload(input_blocks);
      receive_outputs(NBLOCKS, outputs, last_cycle);
    join

    for (int i = 0; i < NBLOCKS; i++)
      recovered[i] = outputs[i];

    if (expected_auth) begin
      for (int i = 0; i < NBLOCKS; i++)
        check($sformatf("decrypt plaintext block %0d", i),
              recovered[i] === plaintext[i]);
    end

    check_response(expected_auth, 1'b0, response_cycle);
    check("decrypt response does not precede the final plaintext transfer",
          response_cycle >= last_cycle);
    $display("  INFO  decrypt response latency after final output: %0d cycles",
             response_cycle - last_cycle);
  endtask

  task automatic test_error_recovery;
    $display("\n--- Contract test: watchdog error recovery ---");
    reset_dut();
    rsp_ready_i = 1'b1;
    send_command(1'b1, '0);
    wait (data_in_ready_o);

    wait (rsp_valid_o && rsp_error_o);
    check("watchdog produces an error response",
          rsp_valid_o && rsp_error_o);
    @(posedge clk_i);
    #1;
    check("error response acknowledges", rsp_valid_o === 1'b0);
    rsp_ready_i = 1'b0;

    send_command(1'b1, '0);
    check("new command does not re-fire the previous error response",
          rsp_valid_o === 1'b0);
    repeat (2) begin
      @(posedge clk_i);
      #1;
      check("response remains clear after recovery command",
            rsp_valid_o === 1'b0);
    end
  endtask

  initial begin
    pass_count = 0;
    fail_count = 0;

    for (int i = 0; i < NBLOCKS; i++) begin
      plaintext[i] = '0;
      for (int byte_idx = 0; byte_idx < 16; byte_idx++)
        plaintext[i] = (plaintext[i] << 8)
                     | 8'((i * 16 + byte_idx) & 8'hff);
    end

    $readmemh("tb/vectors/ct.hex", golden_ct);
    $readmemh("tb/vectors/tag.hex", tag_file);
    golden_tag = tag_file[0];

    test_encrypt();
    test_decrypt(ciphertext, 1'b1);

    for (int i = 0; i < NBLOCKS; i++)
      tampered[i] = ciphertext[i];
    tampered[0] ^= 128'h1;
    test_decrypt(tampered, 1'b0);

    test_error_recovery();

    $display("\n=== v2 contract: %0d passed, %0d failed ===",
             pass_count, fail_count);
    if (fail_count != 0)
      $fatal(1, "AES-GCM v2 external contract failed");

    $display("ALL V2 CONTRACT TESTS PASSED");
    $finish;
  end

  initial begin
    #10_000_000;
    $fatal(1, "v2 contract test timed out");
  end

endmodule
