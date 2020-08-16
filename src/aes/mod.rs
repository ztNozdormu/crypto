// #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod aesni_x86;


pub mod generic;

pub use self::generic::*;
