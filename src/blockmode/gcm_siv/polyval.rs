
// 硬件加速代码参考:
//      https://github.com/Shay-Gueron/AES-GCM-SIV/blob/master/AES_GCM_SIV_128/AES_GCM_SIV_128_Reference_Code/clmul_emulator.c

#[path = "./polyval_generic.rs"]
mod platform;

pub use self::platform::Polyval;
