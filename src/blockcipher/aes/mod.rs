#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    all(target_feature = "aes", target_feature = "sse2")
))]
#[path = "./aesni_x86.rs"]
mod platform;


// AArch64 CPU 特性名称:
// https://github.com/rust-lang/stdarch/blob/master/crates/std_detect/src/detect/arch/aarch64.rs
#[cfg(all(
    target_arch = "aarch64",
    all(target_feature = "neon", target_feature = "crypto")
))]
#[path = "./aesni_aarch64.rs"]
mod platform;


#[cfg(not(any(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        all(target_feature = "aes", target_feature = "sse2")
    ),
    all(
        target_arch = "aarch64",
        all(target_feature = "neon", target_feature = "crypto")
    )
)))]
#[path = "./generic.rs"]
mod platform;

pub use self::platform::*;
