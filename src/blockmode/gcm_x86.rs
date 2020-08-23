#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

// 参考:
// https://www.intel.cn/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf

#[derive(Debug, Clone)]
pub struct GHash {
    h: __m128i,
}

impl GHash {
    pub fn new(hk: &[u8]) -> Self {
        todo!()
    }
    
    // Performing Ghash Using Algorithms 1 and 5 (C)
    fn gf_mul(&self, x: &mut [u8]) {
        debug_assert_eq!(x.len(), 16);

        unsafe {
            let a = self.h;
            let b = _mm_loadu_si128(x.as_ptr() as *const __m128i);

            let mut tmp0: __m128i = core::mem::zeroed();
            let mut tmp1: __m128i = core::mem::zeroed();
            let mut tmp2: __m128i = core::mem::zeroed();
            let mut tmp3: __m128i = core::mem::zeroed();
            let mut tmp4: __m128i = core::mem::zeroed();
            let mut tmp5: __m128i = core::mem::zeroed();
            let mut tmp6: __m128i = core::mem::zeroed();
            let mut tmp7: __m128i = core::mem::zeroed();
            let mut tmp8: __m128i = core::mem::zeroed();
            let mut tmp9: __m128i = core::mem::zeroed();

            tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
            tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
            tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
            tmp6 = _mm_clmulepi64_si128(a, b, 0x11);
            tmp4 = _mm_xor_si128(tmp4, tmp5);
            tmp5 = _mm_slli_si128(tmp4, 8);
            tmp4 = _mm_srli_si128(tmp4, 8);
            tmp3 = _mm_xor_si128(tmp3, tmp5);
            tmp6 = _mm_xor_si128(tmp6, tmp4);
            tmp7 = _mm_srli_epi32(tmp3, 31);
            tmp8 = _mm_srli_epi32(tmp6, 31);
            tmp3 = _mm_slli_epi32(tmp3, 1);
            tmp6 = _mm_slli_epi32(tmp6, 1);
            tmp9 = _mm_srli_si128(tmp7, 12);
            tmp8 = _mm_slli_si128(tmp8, 4);
            tmp7 = _mm_slli_si128(tmp7, 4);
            tmp3 = _mm_or_si128(tmp3, tmp7);
            tmp6 = _mm_or_si128(tmp6, tmp8);
            tmp6 = _mm_or_si128(tmp6, tmp9);
            tmp7 = _mm_slli_epi32(tmp3, 31);
            tmp8 = _mm_slli_epi32(tmp3, 30);
            tmp9 = _mm_slli_epi32(tmp3, 25);
            tmp7 = _mm_xor_si128(tmp7, tmp8);
            tmp7 = _mm_xor_si128(tmp7, tmp9);
            tmp8 = _mm_srli_si128(tmp7, 4);
            tmp7 = _mm_slli_si128(tmp7, 12);
            tmp3 = _mm_xor_si128(tmp3, tmp7);
            tmp2 = _mm_srli_epi32(tmp3, 1);
            tmp4 = _mm_srli_epi32(tmp3, 2);
            tmp5 = _mm_srli_epi32(tmp3, 7);
            tmp2 = _mm_xor_si128(tmp2, tmp4);
            tmp2 = _mm_xor_si128(tmp2, tmp5);
            tmp2 = _mm_xor_si128(tmp2, tmp8);
            tmp3 = _mm_xor_si128(tmp3, tmp2);
            tmp6 = _mm_xor_si128(tmp6, tmp3);

            _mm_storeu_si128(x.as_mut_ptr() as *mut __m128i, tmp6);
        }
    }

    pub fn ghash(&self, data: &mut [u8]) {
        self.gf_mul(data);
    }
}