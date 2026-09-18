# Page format

One command processes exactly one page. The page holds the payload followed by
a fixed 32-byte trailer. The trailer is the same for AES-128 and AES-256
because the GCM tag is always 128 bits and this block fixes the AAD at one
128-bit block.

```
byte offset        content                       beats on data_out (encrypt)
0 .. P-1           ciphertext, P = PAGE_BYTES-32  NBLOCKS beats, CT[0] first
P .. P+15          GCM authentication tag         1 beat
P+16 .. P+31       AAD as given in cmd_aad_i      1 beat, data_out_last_o = 1
```

| PAGE_BYTES | P (payload bytes) | NBLOCKS | encrypt beats | decrypt beats |
|---:|---:|---:|---:|---:|
| 48 | 16 | 1 | 3 | 1 |
| 64 | 32 | 2 | 4 | 2 |
| 256 | 224 | 14 | 16 | 14 |
| 528 | 496 | 31 | 33 | 31 |
| 4096 | 4064 | 254 | 256 | 254 |

Each beat is one 128-bit word. Byte order inside a word follows the
cryptographic reference: `data_out_o[127:120]` is the first byte of the block
(the byte at the lowest page offset), matching `bytes_to_blocks()` in the
cocotb driver and the golden `.hex` vectors. How a downstream FIFO or flash
interface serialises a 128-bit word onto its own bus is outside this block.

## Encrypt

- Input: `NBLOCKS` plaintext beats on `data_in_*`.
- Output: `NBLOCKS` ciphertext beats, then the tag beat, then the AAD beat.
  `data_out_last_o` is high only on the AAD beat.
- Response: `rsp_valid_o` asserts the cycle after the AAD beat is accepted.
  `rsp_auth_ok_o` is hardwired 1 in encrypt mode.

## Decrypt

- Input: `NBLOCKS` ciphertext beats, the expected tag on `cmd_exp_tag_i`, and
  the same IV and AAD that were used for encryption.
- Output: `NBLOCKS` plaintext beats. `data_out_last_o` is high on the final
  plaintext beat. The tag and AAD are not replayed.
- Response: `rsp_valid_o` asserts after tag finalisation, about 261 cycles
  after the final plaintext beat (one 128-cycle GHASH multiply for the length
  block plus the tag compare and the response register). `rsp_auth_ok_o` is 1
  only if the computed tag equals `cmd_exp_tag_i`.

Plaintext is streamed before authentication completes. A consumer that must
not expose unauthenticated data has to buffer the `NBLOCKS` plaintext beats
and release them only on `rsp_valid_o && rsp_auth_ok_o && !rsp_error_o`.

## GCM inputs derived from the page

- Counter blocks: `J0 = {IV[95:0], 32'h1}`, payload block *i* uses counter
  `{IV[95:0], 32'(i + 2)}`.
- GHASH input sequence: AAD block, `NBLOCKS` ciphertext blocks, then the
  length block `{64'(128), 64'(NBLOCKS * 128)}` (bit lengths of AAD and
  ciphertext).
- Tag: `GHASH(...) XOR AES_K(J0)`.

These are exactly NIST SP 800-38D with a 96-bit IV, a single 16-byte AAD, a
16-byte-aligned plaintext and a full 128-bit tag, so any standard library
(the Python `cryptography` package is used throughout the testbenches) is a
valid reference for every supported configuration.
