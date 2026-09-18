// AES-GCM package: FSM state enums, algorithm-fixed GCM geometry and helper
// functions shared by every module of the aes_gcm_ip block.
// Author: Baris. Date: 2026-09-18.
package aes_gcm_pkg;

  // ------------------------------------------------------------------------
  // GCM FSM states, sequenced in sync with the Secworks AES core handshake
  // ------------------------------------------------------------------------
  typedef enum logic [3:0] {
    ST_IDLE,         // Wait for an accepted command
    ST_KEY_INIT,     // Expand the AES key
    ST_GEN_H,        // Encrypt 0^128 to derive the GHASH subkey H
    ST_PREP_J0,      // Initialise GHASH with H (one cycle)
    ST_ENC_J0,       // Encrypt J0 for the final tag mask
    ST_PROC_AAD,     // Feed the single AAD block into GHASH
    ST_PROC_PAYLOAD, // Main loop: CTR encrypt a block, feed CT into GHASH
    ST_FINALIZE      // Feed the length block, compute the tag
  } gcm_fsm_state_t;

  typedef enum logic [0:0] {
    ST_GH_IDLE = 1'b0,
    ST_GH_BUSY = 1'b1
  } ghash_state_e;

  // ------------------------------------------------------------------------
  // Geometry fixed by the GCM algorithm (NIST SP 800-38D), not by the user.
  // The configurable knobs are KEY_W and PAGE_BYTES on aes_gcm_top; every
  // other width parameter defaults to these values and is checked against
  // them at elaboration time.
  // ------------------------------------------------------------------------
  localparam int unsigned GCM_BLOCK_W    = 128;  // AES block width = GHASH word width
  localparam int unsigned GCM_IV_W       = 96;   // Only the 96-bit IV path (J0 = IV || 0^31 || 1) is built
  localparam int unsigned GCM_TAG_W      = 128;  // Full-length tag; truncation not implemented
  localparam int unsigned GCM_AAD_W      = 128;  // Exactly one AAD block for both key sizes
  localparam int unsigned GCM_BLOCK_BYTES = GCM_BLOCK_W / 8;
  localparam int unsigned GCM_META_BYTES = (GCM_TAG_W + GCM_AAD_W) / 8;  // 32 B per page

  // Supported AES key widths. Anything else is rejected at elaboration.
  function automatic bit gcm_key_w_supported(input int unsigned key_w);
    return (key_w == 128) || (key_w == 256);
  endfunction

  // Payload blocks that fit in one page after tag and AAD are reserved.
  function automatic int unsigned gcm_payload_blocks(input int unsigned page_bytes);
    return (page_bytes - GCM_META_BYTES) / GCM_BLOCK_BYTES;
  endfunction

  // Default watchdog threshold per key width. Measured worst-case per-block
  // service time is well below this for both sizes (see docs/verification.md);
  // AES-256 only adds four key-schedule rounds, so the same value is used.
  function automatic int unsigned gcm_wdt_timeout_default(input int unsigned key_w);
    return (key_w == 256) ? 32'd4095 : 32'd4095;
  endfunction

endpackage : aes_gcm_pkg
