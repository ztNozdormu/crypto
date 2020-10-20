#[cfg(any(
    all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sha"),
    all(target_arch = "aarch64", target_feature = "neon", target_feature = "crypto"),
))]
mod shani;

#[cfg(any(
    all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sha"),
    all(target_arch = "aarch64", target_feature = "neon", target_feature = "crypto"),
))]
use self::shani::*;

mod sha256;
mod sha512;

pub use self::sha256::*;
pub use self::sha512::*;
