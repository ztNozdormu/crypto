#[cfg(target_arch = "x86")]
use core::arch::aarch64::*;

use core::mem::transmute;


// 参考: https://github.com/noloader/AES-Intrinsics/blob/master/clmul-arm.c

#[inline]
unsafe fn pmull(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    // Low
    let a: poly64_t = transmute(vgetq_lane_u64(vreinterpretq_u64_u8(a), 0));
    let b: poly64_t = transmute(vgetq_lane_u64(vreinterpretq_u64_u8(b), 0));
    transmute(vmull_p64(a, b))
}

#[inline]
unsafe fn pmull2(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    // High
    let a: poly64_t = transmute(vgetq_lane_u64(vreinterpretq_u64_u8(a), 1));
    let b: poly64_t = transmute(vgetq_lane_u64(vreinterpretq_u64_u8(b), 1));
    transmute(vmull_p64(a, b))
}

// Perform the multiplication and reduction in GF(2^128)
#[inline]
unsafe fn gf_mul(h: uint8x16_t, x: &mut [u8; 16]) {
    // NOTE: 在传入之前 确保 h 的端序。
    let a8 = h;
    
    // 转换端序（vrbitq_u8）
    x.reverse();
    
    // vld1q_u8
    let b8 = transmute(x.clone());

    // polynomial multiply
    let z = vdupq_n_u8(0);
    let mut r0 = pmull(a8, b8);
    let mut r1 = pmull2(a8, b8);
    let mut t0 = vextq_u8(b8, b8, 8);
    let mut t1 = pmull(a8, t0);
    t0 = pmull2(a8, t0);
    t0 = veorq_u8(t0, t1);
    t1 = vextq_u8(z, t0, 8);
    r0 = veorq_u8(r0, t1);
    t1 = vextq_u8(t0, z, 8);
    r1 = veorq_u8(r1, t1);

    // polynomial reduction

    // https://developer.arm.com/architectures/instruction-sets/simd-isas/neon/intrinsics?search=vdupq_n_u64
    // let p = vreinterpretq_u8_u64(vdupq_n_u64(0x0000000000000087));
    let p = transmute(vdupq_n_u64(0x0000000000000087));
    t0 = pmull2(r1, p);
    t1 = vextq_u8(t0, z, 8);
    r1 = veorq_u8(r1, t1);
    t1 = vextq_u8(z, t0, 8);
    r0 = veorq_u8(r0, t1);
    t0 = pmull(r1, p);

    let c8 = veorq_u8(r0, t0);

    // vrbitq_u8
    // vst1q_u8
    // https://developer.arm.com/architectures/instruction-sets/simd-isas/neon/intrinsics?search=vrbitq_u8
    let r: [u8; 16] = transmute(c8);
    x[ 0] = r[15];
    x[ 1] = r[14];
    x[ 2] = r[13];
    x[ 3] = r[12];
    x[ 4] = r[11];
    x[ 5] = r[10];
    x[ 6] = r[ 9];
    x[ 7] = r[ 8];
    x[ 8] = r[ 7];
    x[ 9] = r[ 6];
    x[10] = r[ 5];
    x[11] = r[ 4];
    x[12] = r[ 3];
    x[13] = r[ 2];
    x[14] = r[ 1];
    x[15] = r[ 0];
}

#[derive(Debug, Clone)]
pub struct GHash {
    key: uint8x16_t,
    tag: uint8x16_t,
}

impl GHash {
    pub const KEY_LEN: usize   = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const TAG_LEN: usize   = 16;
    

    pub fn new(h: &[u8; Self::KEY_LEN]) -> Self {
        let mut h = h.clone();
        h.reverse();

        let tag = [0u8; Self::TAG_LEN];

        unsafe {
            Self {
                key: transmute(h),
                tag: transmute(tag),
            }
        }
    }
    
    pub fn update(&mut self, m: &[u8]) {
        let mlen = m.len();

        if mlen == 0 {
            return ();
        }

        let n = mlen / Self::BLOCK_LEN;
        for i in 0..n {
            let chunk = &m[i * Self::BLOCK_LEN..i * Self::BLOCK_LEN + Self::BLOCK_LEN];
            gf_mul(self.key, chunk);
        }

        if mlen % Self::BLOCK_LEN != 0 {
            let rem = &m[n * Self::BLOCK_LEN..];
            let rlen = rem.len();

            let mut last_block = [0u8; Self::BLOCK_LEN];
            last_block[..rlen].copy_from_slice(rem);
            gf_mul(self.key, &last_block);
        }
    }

    pub fn finalize(self) -> [u8; Self::TAG_LEN] {
        unsafe {
            transmute(self.tag)
        }
    }
}