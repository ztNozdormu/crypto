#[cfg(target_arch = "x86")]
use std::arch::x86::{
    _mm_sha1msg1_epu32, _mm_sha1msg2_epu32, _mm_sha1nexte_epu32, _mm_sha1rnds4_epu32, 
    _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32,
};

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{
    _mm_sha1msg1_epu32, _mm_sha1msg2_epu32, _mm_sha1nexte_epu32, _mm_sha1rnds4_epu32, 
    _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32,
};

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::{
    vsha1cq_u32, vsha1h_u32, vsha1mq_u32, vsha1pq_u32, vsha1su0q_u32⚠, vsha1su1q_u32,
    vsha256h2q_u32, vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32,
};

