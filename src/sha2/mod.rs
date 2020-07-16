// #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sha"))]
// #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sha"))]


#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod shani;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use self::shani::*;

pub mod sha256;
pub mod sha512;

pub use self::sha256::*;
pub use self::sha512::*;
