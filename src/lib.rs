// #![feature(const_generics, const_fn, const_generic_impls_guard)]
#![cfg_attr(test, feature(test))]
#![feature(stdsimd)]
#![allow(unused_macros, unused_variables, dead_code, unused_assignments, unused_imports)]

#[cfg(test)]
extern crate test;

// #[allow(unused_imports)]
// #[macro_use]
// extern crate log;
// extern crate rand;
extern crate subtle;
extern crate byteorder;
// extern crate packed_simd;
// extern crate x25519_dalek;
// extern crate ed25519_dalek;
// extern crate num_bigint;

#[cfg(test)]
extern crate hex;


pub mod hash;
pub mod md2;
pub mod md4;
pub mod md5;
pub mod sha1;
pub mod sha2;
// pub mod sha3;

pub mod hmac;
pub mod hkdf;

// pub mod blockmode;
pub mod aes;
pub mod camellia;

pub mod rc4;
pub mod chacha20;
pub mod poly1305;
pub mod chacha20_poly1305;



// RSA
// 
// https://docs.rs/rsa


// ED25519 and X25519
// 
// http://docs.rs/x25519-dalek
// http://docs.rs/ed25519-dalek
// 









