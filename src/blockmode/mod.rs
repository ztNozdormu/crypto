
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
mod ccm;
mod gcm;
mod ocb;
mod siv;
mod gcm_siv;
pub use self::ccm::*;
pub use self::gcm::*;
pub use self::ocb::*;
pub use self::siv::*;
pub use self::gcm_siv::*;



// IEEE P1619™/D16 Standard for Cryptographic Protection of Data on Block-Oriented Storage Devices 
// http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf
// 
// Recommendation for Block Cipher Modes of Operation:  The XTS-AES Mode for Confidentiality on Storage Devices
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38e.pdf
// 
// Disk encryption theory
// https://en.wikipedia.org/wiki/Disk_encryption_theory
// 
// 
// C code
// https://docs.rs/crate/xtsn/0.1.1/source/src/ccrypto.c
// 
// Rust Code
// https://github.com/pheki/xts-mode/blob/master/src/lib.rs
// 
// C Code
// https://github.com/randombit/botan/blob/master/src/lib/modes/xts/xts.cpp



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
    // if s & 0x80000000000000000000000000000000 != 0 {
    //     (s << 1) ^ 0b10000111
    // } else {
    //     s << 1
    // }
    (s << 1) ^ ( (((s as i128) >> 127) as u128) & 0b10000111)
}
