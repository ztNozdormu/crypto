use crate::sha2::sha256::BLOCK_LEN;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

#[cfg(target_arch = "aarch64")]
use crate::sha2::sha256::K32;



#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sha"))]
#[inline]
pub fn sha256_transform_shani(state: &mut [u32; 8], block: &[u8]) {
    // https://docs.rs/sha2ni/0.8.5/src/sha2ni/sha256_intrinsics.rs.html
    // 
    // Process a block with the SHA-256 algorithm.
    // Based on https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-x86.c
    debug_assert_eq!(state.len(), 8);
    debug_assert_eq!(block.len(), BLOCK_LEN);

    unsafe {
        let mut state0: __m128i;
        let mut state1: __m128i;

        let mut msg: __m128i;
        let mut tmp: __m128i;

        let mut msg0: __m128i;
        let mut msg1: __m128i;
        let mut msg2: __m128i;
        let mut msg3: __m128i;

        let abef_save: __m128i;
        let cdgh_save: __m128i;

        #[allow(non_snake_case)]
        let MASK: __m128i = _mm_set_epi64x(
            0x0c0d_0e0f_0809_0a0bu64 as i64,
            0x0405_0607_0001_0203u64 as i64,
        );
        
        // Load initial values
        tmp = _mm_loadu_si128(state.as_ptr().add(0) as *const __m128i);
        state1 = _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i);

        tmp    = _mm_shuffle_epi32(tmp, 0xB1);       // CDAB
        state1 = _mm_shuffle_epi32(state1, 0x1B);    // EFGH
        state0 = _mm_alignr_epi8(tmp, state1, 8);    // ABEF
        state1 = _mm_blend_epi16(state1, tmp, 0xF0); // CDGH

        // Save current state
        abef_save = state0;
        cdgh_save = state1;

        // Rounds 0-3
        msg = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        msg0 = _mm_shuffle_epi8(msg, MASK);
        msg = _mm_add_epi32(msg0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFu64 as i64, 0x71374491428A2F98u64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        // Rounds 4-7
        msg1 = _mm_loadu_si128(block.as_ptr().add(16) as *const __m128i);
        msg1 = _mm_shuffle_epi8(msg1, MASK);
        msg = _mm_add_epi32(msg1, _mm_set_epi64x(0xAB1C5ED5923F82A4u64 as i64, 0x59F111F13956C25Bu64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        // Rounds 8-11
        msg2 = _mm_loadu_si128(block.as_ptr().add(32) as *const __m128i);
        msg2 = _mm_shuffle_epi8(msg2, MASK);
        msg = _mm_add_epi32( msg2, _mm_set_epi64x(0x550C7DC3243185BEu64 as i64, 0x12835B01D807AA98u64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        // Rounds 12-15
        msg3 = _mm_loadu_si128(block.as_ptr().add(48) as *const __m128i);
        msg3 = _mm_shuffle_epi8(msg3, MASK);
        msg = _mm_add_epi32(msg3, _mm_set_epi64x(0xC19BF1749BDC06A7u64 as i64, 0x80DEB1FE72BE5D74u64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        // Rounds 16-19
        msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x240CA1CC0FC19DC6u64 as i64, 0xEFBE4786E49B69C1u64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmp);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        // Rounds 20-23
        msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x76F988DA5CB0A9DCu64 as i64, 0x4A7484AA2DE92C6Fu64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmp);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        // Rounds 24-27
        msg = _mm_add_epi32(msg2, _mm_set_epi64x(0xBF597FC7B00327C8u64 as i64, 0xA831C66D983E5152u64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        // Rounds 28-31
        msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x1429296706CA6351u64 as i64, 0xD5A79147C6E00BF3u64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        // Rounds 32-35
        msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x53380D134D2C6DFCu64 as i64, 0x2E1B213827B70A85u64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmp);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        // Rounds 36-39
        msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x92722C8581C2C92Eu64 as i64, 0x766A0ABB650A7354u64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmp);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        // Rounds 40-43
        msg = _mm_add_epi32(msg2, _mm_set_epi64x(0xC76C51A3C24B8B70u64 as i64, 0xA81A664BA2BFE8A1u64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        // Rounds 44-47
        msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x106AA070F40E3585u64 as i64, 0xD6990624D192E819u64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        // Rounds 48-51
        msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x34B0BCB52748774Cu64 as i64, 0x1E376C0819A4C116u64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmp);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        // Rounds 52-55
        msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x682E6FF35B9CCA4Fu64 as i64, 0x4ED8AA4A391C0CB3u64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmp);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        // Rounds 56-59
        msg = _mm_add_epi32(msg2, _mm_set_epi64x(0x8CC7020884C87814u64 as i64, 0x78A5636F748F82EEu64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        // Rounds 60-63
        msg = _mm_add_epi32(msg3, _mm_set_epi64x(0xC67178F2BEF9A3F7u64 as i64, 0xA4506CEB90BEFFFAu64 as i64));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        // Combine state
        state0 = _mm_add_epi32(state0, abef_save);
        state1 = _mm_add_epi32(state1, cdgh_save);

        tmp    = _mm_shuffle_epi32(state0, 0x1B);    // FEBA
        state1 = _mm_shuffle_epi32(state1, 0xB1);    // DCHG
        state0 = _mm_blend_epi16(tmp, state1, 0xF0); // DCBA
        state1 = _mm_alignr_epi8(state1, tmp, 8);    // ABEF

        // Save state
        _mm_storeu_si128(state.as_mut_ptr().add(0) as *mut __m128i, state0);
        _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, state1);
    }
}


#[cfg(all(target_arch = "aarch64", target_feature = "neon", target_feature = "crypto"))]
#[inline]
pub fn sha256_transform_neon(state: &mut [u32; 8], block: &[u8]) {
    // Process a block with the SHA-256 algorithm.
    // https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-arm.c
    debug_assert_eq!(state.len(), 8);
    debug_assert_eq!(block.len(), BLOCK_LEN);

    // vld1q_u32
    fn uint32x4_t_new(a: u32, b: u32, c: u32, d: u32) -> uint32x4_t {
        let array = [ a, b, c, d ];
        union U {
            array: [u32; 4],
            vec: uint32x4_t,
        }
        unsafe { U { array }.vec }
    }

    fn uint32x4_t_from_be_bytes(data: &[u8]) -> uint32x4_t {
        let a = u32::from_be_bytes([data[ 0], data[ 1], data[ 2], data[ 3]]);
        let b = u32::from_be_bytes([data[ 4], data[ 5], data[ 6], data[ 7]]);
        let c = u32::from_be_bytes([data[ 8], data[ 9], data[10], data[11]]);
        let d = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        uint32x4_t_new(a, b, c, d)
    }

    unsafe {
        // Load state
        let mut state0: uint32x4_t = uint32x4_t_new(state[0], state[1], state[2], state[3]);
        let mut state1: uint32x4_t = uint32x4_t_new(state[4], state[5], state[6], state[7]);
        
        // Save state
        let abef_save: uint32x4_t = state0;
        let cdgh_save: uint32x4_t = state1;

        let mut msg0: uint32x4_t = uint32x4_t_from_be_bytes(&block[ 0..16]);
        let mut msg1: uint32x4_t = uint32x4_t_from_be_bytes(&block[16..32]);
        let mut msg2: uint32x4_t = uint32x4_t_from_be_bytes(&block[32..48]);
        let mut msg3: uint32x4_t = uint32x4_t_from_be_bytes(&block[48..64]);

        let mut tmp0: uint32x4_t;
        let mut tmp1: uint32x4_t;
        let mut tmp2: uint32x4_t;

        tmp0 = vaddq_u32(msg0, uint32x4_t_new(K32[0], K32[1], K32[2], K32[3]));

        // Rounds 0-3
        msg0 = vsha256su0q_u32(msg0, msg1);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, uint32x4_t_new(K32[4], K32[5], K32[6], K32[7]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);

        // Rounds 4-7
        msg1 = vsha256su0q_u32(msg1, msg2);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, uint32x4_t_new(K32[8], K32[9], K32[10], K32[11]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);

        // Rounds 8-11
        msg2 = vsha256su0q_u32(msg2, msg3);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, uint32x4_t_new(K32[12], K32[13], K32[14], K32[15]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);

        // Rounds 12-15
        msg3 = vsha256su0q_u32(msg3, msg0);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg0, uint32x4_t_new(K32[16], K32[17], K32[18], K32[19]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);

        // Rounds 16-19
        msg0 = vsha256su0q_u32(msg0, msg1);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, uint32x4_t_new(K32[20], K32[21], K32[22], K32[23]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);

        // Rounds 20-23
        msg1 = vsha256su0q_u32(msg1, msg2);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, uint32x4_t_new(K32[24], K32[25], K32[26], K32[27]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);

        // Rounds 24-27
        msg2 = vsha256su0q_u32(msg2, msg3);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, uint32x4_t_new(K32[28], K32[29], K32[30], K32[31]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);

        // Rounds 28-31
        msg3 = vsha256su0q_u32(msg3, msg0);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg0, uint32x4_t_new(K32[32], K32[33], K32[34], K32[35]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);

        // Rounds 32-35
        msg0 = vsha256su0q_u32(msg0, msg1);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, uint32x4_t_new(K32[36], K32[37], K32[38], K32[39]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg0 = vsha256su1q_u32(msg0, msg2, msg3);

        // Rounds 36-39
        msg1 = vsha256su0q_u32(msg1, msg2);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, uint32x4_t_new(K32[40], K32[41], K32[42], K32[43]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg1 = vsha256su1q_u32(msg1, msg3, msg0);

        // Rounds 40-43
        msg2 = vsha256su0q_u32(msg2, msg3);
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, uint32x4_t_new(K32[44], K32[45], K32[46], K32[47]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);
        msg2 = vsha256su1q_u32(msg2, msg0, msg1);

        // Rounds 44-47
        msg3 = vsha256su0q_u32(msg3, msg0);
        tmp2 = state0;
        tmp0 = vaddq_u32(msg0, uint32x4_t_new(K32[48], K32[49], K32[50], K32[51]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);
        msg3 = vsha256su1q_u32(msg3, msg1, msg2);

        // Rounds 48-51
        tmp2 = state0;
        tmp1 = vaddq_u32(msg1, uint32x4_t_new(K32[52], K32[53], K32[54], K32[55]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);

        // Rounds 52-55
        tmp2 = state0;
        tmp0 = vaddq_u32(msg2, uint32x4_t_new(K32[56], K32[57], K32[58], K32[59]));
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);

        // Rounds 56-59
        tmp2 = state0;
        tmp1 = vaddq_u32(msg3, uint32x4_t_new(K32[60], K32[61], K32[62], K32[63]));
        state0 = vsha256hq_u32(state0, state1, tmp0);
        state1 = vsha256h2q_u32(state1, tmp2, tmp0);

        // Rounds 60-63
        tmp2 = state0;
        state0 = vsha256hq_u32(state0, state1, tmp1);
        state1 = vsha256h2q_u32(state1, tmp2, tmp1);

        // Combine state
        state0 = vaddq_u32(state0, abef_save);
        state1 = vaddq_u32(state1, cdgh_save);
        
        // vst1q_u32
        #[inline]
        fn save_state(state: &mut [u32], vec: uint32x4_t) {
            union U {
                array: [u32; 4],
                vec: uint32x4_t,
            }
            let array = unsafe { U { vec }.array };
            state[0] = array[0];
            state[1] = array[1];
            state[2] = array[2];
            state[3] = array[3];
        }

        // Save state
        save_state(&mut state[0..4], state0);
        save_state(&mut state[4..8], state1);
    }
}
