// The OCB Authenticated-Encryption Algorithm
// https://tools.ietf.org/html/rfc7253
// 
// OCB: A Block-Cipher Mode of Operation for Efficient Authenticated Encryption
// https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/ocb/ocb-spec.pdf

use crate::aes::generic::ExpandedKey128;

use subtle;


const BLOCK_LEN: usize = 16;
const TAG_LEN: usize   = 16; // 16-Bytes, 128-Bits
const IV_LEN: usize    = 12; // 12-Bytes,  96-Bits
