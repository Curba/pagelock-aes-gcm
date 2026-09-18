// AES-128-GCM Timeout and Error Recovery Testbench
`timescale 1ns/1ps

module tb_aes_gcm_timeout;
    // Default geometry of aes_gcm_top (AES-128, 256-byte page)
    localparam int KEY_W  = 128;
    localparam int IV_W   = 96;
    localparam int TAG_W  = 128;
    localparam int DATA_W = 128;
    localparam int AAD_W  = 128;
    import aes_gcm_pkg::*;

    // -------------------------------------------------------------------------
    // Signals
    // -------------------------------------------------------------------------
    logic                clk_i;
    logic                rst_ni;

    // Operation
    logic                cipher_start_i;
    logic                cipher_mode_i;
    logic [TAG_W-1:0]    cipher_exp_tag_i;

    // Key & IV
    logic [IV_W-1:0]     cipher_iv_i;
    logic [KEY_W-1:0]    cipher_key_i;
    logic                cipher_key_valid_i;
    logic                cipher_key_consumed_o;
    logic                cipher_key_ready_o;

    // Data & AAD
    logic [AAD_W-1:0]    cipher_aad_i;
    logic                cipher_aad_valid_i;
    logic                cipher_aad_ready_o;
    logic [DATA_W-1:0]   cipher_plaintext_data_i;
    logic [DATA_W-1:0]   cipher_spi_data_i;
    logic                cipher_data_in_valid_i;
    logic                cipher_data_in_ready_o;
    
    // Outputs
    logic                cipher_tag_ok_o;
    logic                cipher_busy_o;
    logic                cipher_done_o;
    logic                cipher_err_o;
    logic [DATA_W-1:0]   cipher_data_out_o;
    logic                cipher_data_out_valid_o;
    logic                cipher_data_out_ready_i;
    logic                cipher_data_out_last_o;
    logic                cipher_page_done_o;
    logic [4:0]          cipher_total_blocks_o;
    logic [3:0]          cipher_state_o;

    // -------------------------------------------------------------------------
    // DUT Instantiation
    // -------------------------------------------------------------------------
    aes_gcm_top dut (
      .clk_i            (clk_i),
      .rst_ni           (rst_ni),
      .cmd_valid_i      (cipher_start_i),
      .cmd_ready_o      (cipher_aad_ready_o),
      .cmd_mode_i       (cipher_mode_i),
      .cmd_key_i        (cipher_key_i),
      .cmd_iv_i         (cipher_iv_i),
      .cmd_aad_i        (cipher_aad_i),
      .cmd_exp_tag_i    (cipher_exp_tag_i),
      .data_in_valid_i  (cipher_data_in_valid_i),
      .data_in_ready_o  (cipher_data_in_ready_o),
      .data_in_i        (cipher_mode_i ? cipher_plaintext_data_i : cipher_spi_data_i),
      .data_out_o       (cipher_data_out_o),
      .data_out_valid_o (cipher_data_out_valid_o),
      .data_out_ready_i (cipher_data_out_ready_i),
      .data_out_last_o  (cipher_data_out_last_o),
      .rsp_valid_o      (cipher_done_o),
      .rsp_ready_i      (1'b1),
      .rsp_auth_ok_o    (cipher_tag_ok_o),
      .rsp_error_o      (cipher_err_o)
    );

    assign cipher_key_consumed_o = cipher_start_i && cipher_aad_ready_o;
    assign cipher_key_ready_o    = cipher_aad_ready_o;
    assign cipher_busy_o         = !cipher_aad_ready_o;
    assign cipher_page_done_o    = cipher_done_o;
    assign cipher_total_blocks_o = cipher_mode_i ? 5'd16 : 5'd14;
    assign cipher_state_o        = '0;

    // -------------------------------------------------------------------------
    // Clock Generation (100 MHz -> 10ns period)
    // -------------------------------------------------------------------------
    initial begin
        clk_i = 0;
        forever #5 clk_i = ~clk_i;
    end

    // -------------------------------------------------------------------------
    // Test Sequence
    // -------------------------------------------------------------------------
    initial begin
        $dumpfile("timeout_waves.vcd");
        $dumpvars(0, tb_aes_gcm_timeout);

        // 1. Reset and Default State
        rst_ni                  = 1'b0;
        cipher_start_i          = 1'b0;
        cipher_mode_i           = 1'b1; // Encrypt
        cipher_key_valid_i      = 1'b0;
        cipher_data_in_valid_i  = 1'b0;
        cipher_data_out_ready_i = 1'b1;
        cipher_key_i            = 128'hDEADBEEF_00000000_00000000_00000000;
        cipher_iv_i             = 96'hCAFEBAAC_00000000_00000000;
        cipher_aad_i            = '0;
        cipher_aad_valid_i      = 1'b0;
        cipher_plaintext_data_i = '0;
        cipher_spi_data_i       = '0;
        cipher_exp_tag_i        = '0;

        #25 rst_ni = 1'b1;
        @(posedge clk_i);

        // 2. Launch Encryption Operation
        $display("[%0t] Starting AES-GCM operation...", $time);
        cipher_start_i      = 1'b1;
        cipher_key_valid_i  = 1'b1;
        cipher_aad_valid_i  = 1'b1;  // assert with start; deassert after FSM pulses aad_ready_o
        // Deassert one cycle after the consume-ready pulse fires
        fork
          begin
            @(posedge cipher_aad_ready_o);
            @(posedge clk_i); #1;
            cipher_aad_valid_i = 1'b0;
          end
        join_none

        @(posedge clk_i iff cipher_aad_ready_o); #1;
        cipher_start_i     = 1'b0;
        cipher_key_valid_i = 1'b0;

        // 3. Wait for FSM to reach payload processing (expecting data)
        wait(cipher_data_in_ready_o == 1'b1);
        $display("[%0t] FSM is requesting data. Simulating upstream FIFO stall...", $time);

        // 4. Starve the bus.
        // We set our watchdog to 4095 cycles. At 100MHz (10ns), that is 40,950ns.
        // We will wait 42,000ns to ensure the watchdog trips.
        #42000;

        // 5. Assertions for Sticky Error & Deadlock Recovery
        @(posedge clk_i);
        if (cipher_err_o === 1'b1) 
            $display("[%0t] PASS: Sticky error flag (cipher_err_o) successfully asserted.", $time);
        else 
            $error("[%0t] FAIL: Watchdog failed to trip or cipher_err_o is not wired correctly.", $time);

        if (cipher_busy_o === 1'b0) 
            $display("[%0t] PASS: FSM recovered to IDLE (cipher_busy_o dropped). No deadlock.", $time);
        else 
            $error("[%0t] FAIL: FSM is deadlocked in busy state.", $time);

        // 6. Verify Error Clears on Next Start (Issue #5 requirement)
        $display("[%0t] Pulsing start_i to check error clearing...", $time);
        cipher_start_i     = 1'b1;
        cipher_key_valid_i = 1'b1;
        @(posedge clk_i iff cipher_aad_ready_o); #1;
        cipher_start_i     = 1'b0;
        cipher_key_valid_i = 1'b0;
        @(posedge clk_i);

        if (cipher_err_o === 1'b0) 
            $display("[%0t] PASS: Error flag correctly cleared on new start.", $time);
        else 
            $error("[%0t] FAIL: Sticky error flag failed to clear.", $time);

        $display("========================================");
        $display("Timeout & Error Recovery testing complete.");
        $display("========================================");
        $finish;
    end
endmodule
