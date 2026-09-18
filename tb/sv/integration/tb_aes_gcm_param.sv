// Purpose: Parameter regression for aes_gcm_top. Instantiates the block in
//          several non-default configurations side by side and runs, for each:
//            1. encrypt: CT blocks and tag against golden vectors,
//               output count = NBLOCKS+2, last on the AAD beat, AAD replayed
//            2. decrypt of the golden page: plaintext recovered, rsp_auth_ok_o=1,
//               output count = NBLOCKS, last on the final PT beat
//            3. tampered decrypt (CT[0] bit 0 flipped): rsp_auth_ok_o=0
//          Golden vectors: scripts/gen_gcm_vectors.py --all
//            key   AES-128: 2b7e1516...  AES-256: FIPS-197 C.3 key 603deb10...
//            iv    cafebabefacedbaddecaf888
//            aad   feedfacedeadbeeffeedfacedeadbeef
//            pt    byte i = i & 0xff
// Author: Baris
// Date: 2026-09-18
`timescale 1ns/1ps

// One configuration under test. Self-contained: clock, reset, stimulus, checks.
module tb_aes_gcm_param_unit #(
  parameter int unsigned KEY_W      = 256,
  parameter int unsigned PAGE_BYTES = 64,
  parameter string       CT_FILE    = "tb/vectors/ct_k256_p64.hex",
  parameter string       TAG_FILE   = "tb/vectors/tag_k256_p64.hex",
  parameter int          READY_PERIOD = 1    // ready high 1 of READY_PERIOD cycles
) (
  output logic done_o,
  output int   pass_o,
  output int   fail_o
);
  localparam int CLK_HALF = 5;
  localparam int unsigned NBLOCKS = (PAGE_BYTES - 32) / 16;
  localparam int unsigned ENC_BLOCKS = NBLOCKS + 2;
  localparam string TAG_STR = $sformatf("[K%0d P%0d]", KEY_W, PAGE_BYTES);

  localparam logic [127:0] KEY128 = 128'h2b7e151628aed2a6abf7158809cf4f3c;
  localparam logic [255:0] KEY256 = 256'h603deb1015ca71be2b73aef0857d7781_1f352c073b6108d72d9810a30914dff4;
  localparam logic [95:0]  IV     = 96'hcafebabe_facedbad_decaf888;
  localparam logic [127:0] AAD    = 128'hfeedface_deadbeef_feedface_deadbeef;

  logic clk_i = 1'b0;
  logic rst_ni;
  logic cmd_valid_i, cmd_ready_o, cmd_mode_i;
  logic [KEY_W-1:0] cmd_key_i;
  logic [95:0]  cmd_iv_i;
  logic [127:0] cmd_aad_i, cmd_exp_tag_i;
  logic data_in_valid_i, data_in_ready_o;
  logic [127:0] data_in_i;
  logic [127:0] data_out_o;
  logic data_out_valid_o, data_out_ready_i, data_out_last_o;
  logic rsp_valid_o, rsp_ready_i, rsp_auth_ok_o, rsp_error_o;

  logic [127:0] golden_ct [NBLOCKS];
  logic [127:0] golden_tag_arr [1];
  logic [127:0] plaintext [NBLOCKS];
  logic [127:0] captured [ENC_BLOCKS];
  logic [127:0] tampered [NBLOCKS];
  int n_out;
  int last_idx;
  int ready_cnt;

  aes_gcm_top #(.KEY_W(KEY_W), .PAGE_BYTES(PAGE_BYTES)) dut (
    .clk_i, .rst_ni,
    .cmd_valid_i, .cmd_ready_o, .cmd_mode_i, .cmd_key_i, .cmd_iv_i, .cmd_aad_i, .cmd_exp_tag_i,
    .data_in_valid_i, .data_in_ready_o, .data_in_i,
    .data_out_o, .data_out_valid_o, .data_out_ready_i, .data_out_last_o,
    .rsp_valid_o, .rsp_ready_i, .rsp_auth_ok_o, .rsp_error_o
  );

  always #CLK_HALF clk_i = ~clk_i;

  // Periodic backpressure pattern on the output, and a free-running cycle counter
  int unsigned cyc;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin ready_cnt <= 0; cyc <= 0; end
    else begin ready_cnt <= (ready_cnt + 1) % READY_PERIOD; cyc <= cyc + 1; end
  end
  assign data_out_ready_i = (ready_cnt == 0);

  task automatic check(input string name, input logic cond);
    if (cond) begin
      $display("  PASS  %s %s", TAG_STR, name); pass_o++;
    end else begin
      $display("  FAIL  %s %s", TAG_STR, name); fail_o++;
    end
  endtask

  task automatic reset_dut;
    rst_ni = 1'b0; cmd_valid_i = 1'b0; cmd_mode_i = 1'b0; cmd_key_i = '0; cmd_iv_i = '0;
    cmd_aad_i = '0; cmd_exp_tag_i = '0; data_in_valid_i = 1'b0; data_in_i = '0; rsp_ready_i = 1'b0;
    repeat (4) @(posedge clk_i); #1; rst_ni = 1'b1; @(posedge clk_i); #1;
  endtask

  // Handshake helper: sample `ready` at the falling edge (stable, pre-edge
  // value), then cross the rising edge. Returns after the edge at which the
  // transfer happened. Stimulus is changed only after the edge (#1).
  task automatic wait_transfer(ref logic ready);
    logic r;
    do begin
      @(negedge clk_i); r = ready;
      `ifdef DEBUG_PARAM $display("  DBG   %s wt r=%b cmd_rdy=%b din_rdy=%b rsp_v=%b st=%0d aes_rdy=%b aes_init=%b key_sent=%b wdt=%0d @%0t", TAG_STR, r, cmd_ready_o, data_in_ready_o, rsp_valid_o, dut.u_aes_fsm.state_q, dut.aes_ready_w, dut.aes_init_w, dut.u_aes_fsm.key_init_sent_q, dut.u_aes_fsm.watchdog_ctr_q, $time); `endif
      @(posedge clk_i);
    end while (!r);
    #1;
  endtask

  // Issue one command and hold until accepted
  task automatic send_cmd(input logic mode, input logic [127:0] exp_tag);
    cmd_mode_i = mode; cmd_iv_i = IV; cmd_aad_i = AAD; cmd_exp_tag_i = exp_tag;
    if (KEY_W == 256) cmd_key_i = KEY_W'(KEY256); else cmd_key_i = KEY_W'(KEY128);
    cmd_valid_i = 1'b1;
    wait_transfer(cmd_ready_o);
    cyc_accept = cyc;
    cmd_valid_i = 1'b0; cmd_key_i = '0;
    $display("  INFO  %s command accepted (mode=%0d) @%0t", TAG_STR, mode, $time);
  endtask

  // Feed NBLOCKS input blocks (ready/valid) from an array. Reports the
  // command-accept to first-input-accept latency (key schedule + H + J0 + AAD).
  int unsigned cyc_accept, cyc_in0;
  task automatic feed(input logic [127:0] blocks [NBLOCKS]);
    for (int i = 0; i < NBLOCKS; i++) begin
      data_in_i = blocks[i]; data_in_valid_i = 1'b1;
      wait_transfer(data_in_ready_o);
      data_in_valid_i = 1'b0;
      if (i == 0) begin
        cyc_in0 = cyc;
        $display("  INFO  %s first input accepted %0d cycles after command accept",
                 TAG_STR, cyc - cyc_accept);
      end
      if (i == 1)
        $display("  INFO  %s input cadence %0d cycles per block", TAG_STR, cyc - cyc_in0);
      `ifdef DEBUG_PARAM $display("  DBG   %s in[%0d] accepted @%0t", TAG_STR, i, $time); `endif
    end
  endtask

  // Capture output beats until `count` have transferred; record where last fired.
  // Samples at the falling edge: valid && ready there means a transfer at the
  // next rising edge.
  task automatic capture(input int count);
    n_out = 0; last_idx = -1;
    while (n_out < count) begin
      @(negedge clk_i);
      if (data_out_valid_o && data_out_ready_i) begin
        captured[n_out] = data_out_o;
        if (data_out_last_o) last_idx = n_out;
        `ifdef DEBUG_PARAM $display("  DBG   %s out[%0d] last=%0d @%0t", TAG_STR, n_out, data_out_last_o, $time); `endif
        n_out++;
      end
      @(posedge clk_i);
    end
    #1;
  endtask

  task automatic ack_rsp;
    logic v;
    do begin @(negedge clk_i); v = rsp_valid_o; @(posedge clk_i); end while (!v);
    #1; rsp_ready_i = 1'b1;
    $display("  INFO  %s response %0d cycles after command accept (mode=%0d)",
             TAG_STR, cyc - cyc_accept, cmd_mode_i);
    @(posedge clk_i); #1; rsp_ready_i = 1'b0;
  endtask

  logic ct_ok, pt_ok;
  int extra_beats;

  initial begin
    done_o = 1'b0; pass_o = 0; fail_o = 0;
    $readmemh(CT_FILE, golden_ct);
    $readmemh(TAG_FILE, golden_tag_arr);
    for (int i = 0; i < NBLOCKS; i++)
      for (int b = 0; b < 16; b++)
        plaintext[i][127 - 8*b -: 8] = 8'((i * 16 + b) & 255);

    $display("%s NBLOCKS=%0d READY_PERIOD=%0d", TAG_STR, NBLOCKS, READY_PERIOD);

    // ---------------- 1. encrypt ----------------
    reset_dut();
    check("cmd_ready_o high after reset", cmd_ready_o === 1'b1);
    fork
      begin send_cmd(1'b1, '0); feed(plaintext); end
      capture(ENC_BLOCKS);
    join
    ct_ok = 1'b1;
    for (int i = 0; i < NBLOCKS; i++) if (captured[i] !== golden_ct[i]) ct_ok = 1'b0;
    check("encrypt: all CT blocks match golden", ct_ok);
    check("encrypt: tag beat matches golden", captured[NBLOCKS] === golden_tag_arr[0]);
    check("encrypt: AAD beat replays command AAD", captured[NBLOCKS + 1] === AAD);
    check("encrypt: last asserted on final beat only", last_idx == ENC_BLOCKS - 1);
    ack_rsp();
    check("encrypt: rsp_auth_ok_o=1, rsp_error_o=0", rsp_auth_ok_o === 1'b1 && rsp_error_o === 1'b0);
    extra_beats = 0;
    repeat (20) begin @(negedge clk_i); if (data_out_valid_o) extra_beats++; end
    @(posedge clk_i); #1;   // stimulus below changes only after an edge
    check("encrypt: no output beats after response", extra_beats == 0);
    check("encrypt: cmd_ready_o high after response", cmd_ready_o === 1'b1);

    // ---------------- 2. decrypt (no reset between commands) ----------------
    `ifdef DEBUG_PARAM $display("  DBG   %s entering decrypt phase @%0t", TAG_STR, $time); `endif
    fork
      begin send_cmd(1'b0, golden_tag_arr[0]); feed(golden_ct); end
      capture(NBLOCKS);
    join
    pt_ok = 1'b1;
    for (int i = 0; i < NBLOCKS; i++) if (captured[i] !== plaintext[i]) pt_ok = 1'b0;
    check("decrypt: plaintext recovered", pt_ok);
    check("decrypt: last asserted on final PT beat only", last_idx == NBLOCKS - 1);
    check("decrypt: response not yet valid at last PT beat", rsp_valid_o === 1'b0);
    ack_rsp();
    check("decrypt: rsp_auth_ok_o=1", rsp_auth_ok_o === 1'b1 && rsp_error_o === 1'b0);

    // ---------------- 3. tampered decrypt ----------------
    reset_dut();
    tampered = golden_ct; tampered[0][0] = ~tampered[0][0];
    fork
      begin send_cmd(1'b0, golden_tag_arr[0]); feed(tampered); end
      capture(NBLOCKS);
    join
    ack_rsp();
    check("tamper: rsp_auth_ok_o=0", rsp_auth_ok_o === 1'b0);
    check("tamper: rsp_error_o=0", rsp_error_o === 1'b0);

    done_o = 1'b1;
  end
endmodule


module tb_aes_gcm_param;
  logic d0, d1, d2, d3, d4;
  int p0, p1, p2, p3, p4, f0, f1, f2, f3, f4;

  tb_aes_gcm_param_unit #(.KEY_W(256), .PAGE_BYTES(64),
    .CT_FILE("tb/vectors/ct_k256_p64.hex"),  .TAG_FILE("tb/vectors/tag_k256_p64.hex"),  .READY_PERIOD(1)) u0 (.done_o(d0), .pass_o(p0), .fail_o(f0));
  tb_aes_gcm_param_unit #(.KEY_W(128), .PAGE_BYTES(48),
    .CT_FILE("tb/vectors/ct_k128_p48.hex"),  .TAG_FILE("tb/vectors/tag_k128_p48.hex"),  .READY_PERIOD(3)) u1 (.done_o(d1), .pass_o(p1), .fail_o(f1));
  tb_aes_gcm_param_unit #(.KEY_W(256), .PAGE_BYTES(528),
    .CT_FILE("tb/vectors/ct_k256_p528.hex"), .TAG_FILE("tb/vectors/tag_k256_p528.hex"), .READY_PERIOD(2)) u2 (.done_o(d2), .pass_o(p2), .fail_o(f2));
  tb_aes_gcm_param_unit #(.KEY_W(256), .PAGE_BYTES(256),
    .CT_FILE("tb/vectors/ct_k256_p256.hex"), .TAG_FILE("tb/vectors/tag_k256_p256.hex"), .READY_PERIOD(1)) u3 (.done_o(d3), .pass_o(p3), .fail_o(f3));
  // Default configuration against the legacy golden vectors (timing reference)
  tb_aes_gcm_param_unit #(.KEY_W(128), .PAGE_BYTES(256),
    .CT_FILE("tb/vectors/ct.hex"),           .TAG_FILE("tb/vectors/tag.hex"),           .READY_PERIOD(1)) u4 (.done_o(d4), .pass_o(p4), .fail_o(f4));

  initial begin
    wait (d0 && d1 && d2 && d3 && d4);
    #20;
    $display("");
    $display("tb_aes_gcm_param: %0d passed, %0d failed", p0 + p1 + p2 + p3 + p4, f0 + f1 + f2 + f3 + f4);
    if (f0 + f1 + f2 + f3 + f4 != 0) $display("RESULT: FAIL");
    else $display("RESULT: PASS");
    $finish;
  end

  initial begin
    #20_000_000;
    $display("tb_aes_gcm_param: TIMEOUT");
    $display("RESULT: FAIL");
    $finish;
  end
endmodule
