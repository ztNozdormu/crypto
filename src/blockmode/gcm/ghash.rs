
// #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "pclmulqdq"))]
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
#[path = "./ghash_x86.rs"]
mod platform;

// NOTE:
//      Crypto: AES + PMULL + SHA1 + SHA2
//      https://github.com/rust-lang/stdarch/blob/master/crates/std_detect/src/detect/arch/aarch64.rs#L26
#[cfg(all(target_arch = "aarch64", target_feature = "pmull"))]
#[path = "./ghash_aarch64.rs"]
mod platform;

#[cfg(all(
    // not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "pclmulqdq")),
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes")),
    not(all(target_arch = "aarch64", target_feature = "pmull")),
))]
#[path = "./ghash_generic.rs"]
mod platform;

pub use self::platform::GHash;

