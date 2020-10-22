#[cfg(not(any(
    all(any(target_arch = "x86", target_arch = "x86_64"), all(target_feature = "sse2", target_feature = "pclmulqdq")),
)))]
#[path = "./generic.rs"]
mod platform;


#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), all(target_feature = "sse2", target_feature = "pclmulqdq")))]
#[path = "./x86.rs"]
mod platform;


pub use self::platform::Polyval;