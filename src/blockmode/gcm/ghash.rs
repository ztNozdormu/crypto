
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "pclmulqdq"))]
#[path = "./ghash_x86.rs"]
mod platform;

// AArch64 平台的 扩展特性名字
// https://github.com/rust-lang/stdarch/pull/739/files#diff-45457821ebcd89871c2789c37332712bfc30fd47cd1c57c83d8c7d0697b4e852R16
// https://en.wikichip.org/wiki/arm/armv8
// https://github.com/rust-lang/stdarch/blob/master/crates/std_detect/src/detect/arch/aarch64.rs
#[cfg(all(target_arch = "aarch64", target_feature = "pmull"))]
#[path = "./ghash_aarch64.rs"]
mod platform;

#[cfg(all(
    not(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "pclmulqdq")),
    not(all(target_arch = "aarch64", target_feature = "pmull")),
))]
#[path = "./ghash_generic.rs"]
mod platform;

pub use self::platform::GHash;

