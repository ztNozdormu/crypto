#![cfg_attr(test, feature(test))]
#![feature(stdsimd, llvm_asm)]
#![allow(unused_macros, unused_variables, dead_code, unused_assignments, unused_imports)]

// #![no_std]

#[cfg(test)]
extern crate test;

extern crate subtle;

#[cfg(test)]
extern crate hex;


mod util;
// pub mod error;

// cryptographic hash function (CHF)
pub mod hash;

// Key derivation function (KDF)
pub mod kdf;

pub mod mac;

pub mod cipher;
pub mod blockmode;

pub mod blockcipher;
pub mod streamcipher;
pub mod aeadcipher;



// Elliptic Curve Cryptography（ECC）
// http://docs.rs/x25519-dalek
// http://docs.rs/ed25519-dalek

// RSA
// https://docs.rs/rsa


// pub mod scrypt; // TODO
// The scrypt Password-Based Key Derivation Function
// https://tools.ietf.org/html/rfc7914
// 
// https://en.wikipedia.org/wiki/Scrypt#Algorithm