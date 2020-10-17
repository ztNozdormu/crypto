
// Recommendation for Block Cipher Modes of Operation (ECB/CBC/CFB/OFB/CTR)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf


mod ecb;
mod cbc;
mod cfb;
mod ofb;
mod ctr;
pub use self::ecb::*;
pub use self::cbc::*;
pub use self::cfb::*;
pub use self::ofb::*;
pub use self::ctr::*;


// AEAD
pub mod ccm;
pub mod gcm;
pub mod ocb;
pub mod siv;
pub mod gcm_siv;

// pub mod xts;


#[allow(dead_code)]
#[inline]
fn dbl2(s: u128) -> u128 {
    if s & 0x80000000000000000000000000000000 != 0 {
        (s << 1) ^ 0b10000111
    } else {
        s << 1
    }
}

// 2.  Notation and Basic Operations
// https://tools.ietf.org/html/rfc7253#section-2
// 
// double(S)     If S[1] == 0, then double(S) == (S[2..128] || 0);
//              otherwise, double(S) == (S[2..128] || 0) xor
//              (zeros(120) || 10000111).
// 
// https://github.com/briansmith/ring/issues/517
#[inline]
pub(crate) const fn dbl(s: u128) -> u128 {
    (s << 1) ^ ( (((s as i128) >> 127) as u128) & 0b10000111)
}
