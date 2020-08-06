// FIPS-180-2 compliant SHA-256 implementation
// 
// The SHA-256 Secure Hash Standard was published by NIST in 2002.
// http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
// 

use byteorder::{BE, ByteOrder};

use std::convert::TryFrom;

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sha"))]
use crate::sha2::shani::sha256_transform_shani;
#[cfg(all(target_arch = "aarch64", target_feature = "neon", target_feature = "crypto"))]
use crate::sha2::shani::sha256_transform_neon;


pub const BLOCK_LEN: usize  = 64;
pub const DIGEST_LEN: usize = 32;

// Round constants
pub const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 
];

pub const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

macro_rules! CH {
    ($x:expr, $y:expr, $z:expr) => (
        ( ($x) & ($y) ) ^ ( !($x) & ($z) )
    )
}
macro_rules! MAJ {
    ($x:expr, $y:expr, $z:expr) => (
        ( ($x) & ($y) ) ^ ( ($x) & ($z) ) ^ ( ($y) & ($z) )
    )
}
macro_rules! EP0 {
    ($v:expr) => (
        $v.rotate_right(2) ^ $v.rotate_right(13) ^ $v.rotate_right(22)
    )
}
macro_rules! EP1 {
    ($v:expr) => (
        $v.rotate_right(6) ^ $v.rotate_right(11) ^ $v.rotate_right(25)
    )
}
macro_rules! SIG0 {
    ($v:expr) => (
        $v.rotate_right(7) ^ $v.rotate_right(18) ^ ($v >> 3)
    )
}
macro_rules! SIG1 {
    ($v:expr) => (
        $v.rotate_right(17) ^ $v.rotate_right(19) ^ ($v >> 10)
    )
}


#[inline]
pub fn sha256_transform_generic(state: &mut [u32; 8], block: &[u8]) {
    debug_assert_eq!(state.len(), 8);
    debug_assert_eq!(block.len(), BLOCK_LEN);
    
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i*4 + 0], block[i*4 + 1],
            block[i*4 + 2], block[i*4 + 3],
        ]);
    }
    for t in 16..64 {
        w[t] = SIG1!(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(SIG0!(w[t - 15]))
                .wrapping_add(w[t - 16]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    
    for i in 0..64 {
        let t1 = h.wrapping_add(EP1!(e))
                .wrapping_add(CH!(e, f, g))
                .wrapping_add(K32[i])
                .wrapping_add(w[i]);
        let t2 = EP0!(a).wrapping_add(MAJ!(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[allow(unreachable_code)]
#[inline]
pub fn sha256_transform(state: &mut [u32; 8], block: &[u8]) {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sha"))]
    {
        return sha256_transform_shani(state, block);
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon", target_feature = "crypto"))]
    {
        return sha256_transform_neon(state, block);
    }

    return sha256_transform_generic(state, block);
}


#[derive(Clone)]
pub struct Sha256 {
    buffer: [u8; 64],
    state: [u32; 8],
    len: usize,      // in bytes.
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            buffer: [0u8; 64],
            state: INITIAL_STATE,
            len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut n = self.len % BLOCK_LEN;
        if n != 0 {
            let mut i = 0usize;
            loop {
                if n == 64 || i >= data.len() {
                    break;
                }
                self.buffer[n] = data[i];
                n += 1;
                i += 1;
                self.len += 1;
            }

            if self.len % BLOCK_LEN != 0 {
                return ();
            } else {
                sha256_transform(&mut self.state, &self.buffer);

                let data = &data[i..];
                if data.len() > 0 {
                    return self.update(data);
                }
            }
        }

        if data.len() < 64 {
            self.buffer[..data.len()].copy_from_slice(data);
            self.len += data.len();
        } else if data.len() == 64 {
            sha256_transform(&mut self.state, data);
            self.len += 64;
        } else if data.len() > 64 {
            let blocks = data.len() / 64;
            for i in 0..blocks {
                sha256_transform(&mut self.state, &data[i*64..i*64+64]);
                self.len += 64;
            }
            let data = &data[blocks*64..];
            if data.len() > 0 {
                self.buffer[..data.len()].copy_from_slice(data);
                self.len += data.len();
            }
        } else {
            unreachable!()
        }
    }

    pub fn finalize(&mut self) {
        let len_bits = u64::try_from(self.len).unwrap() * 8;
        let n = self.len % BLOCK_LEN;
        if n == 0 {
            let mut block = [0u8; 64];
            block[0] = 0x80;
            block[56..].copy_from_slice(&len_bits.to_be_bytes());
            sha256_transform(&mut self.state, &block);
        } else {
            self.buffer[n] = 0x80;
            for i in n+1..64 {
                self.buffer[i] = 0;
            }
            if 64 - n - 1 >= 8 {
                self.buffer[56..].copy_from_slice(&len_bits.to_be_bytes());
                sha256_transform(&mut self.state, &self.buffer);
            } else {
                sha256_transform(&mut self.state, &self.buffer);
                let mut block = [0u8; 64];
                block[56..].copy_from_slice(&len_bits.to_be_bytes());
                sha256_transform(&mut self.state, &block);
            }
        }
    }

    pub fn state(&self) -> &[u32; 8] {
        &self.state
    }

    pub fn output(self) -> [u8; DIGEST_LEN] {
        let mut output = [0u8; 32];
        BE::write_u32(&mut output[ 0.. 4], self.state[0]);
        BE::write_u32(&mut output[ 4.. 8], self.state[1]);
        BE::write_u32(&mut output[ 8..12], self.state[2]);
        BE::write_u32(&mut output[12..16], self.state[3]);
        BE::write_u32(&mut output[16..20], self.state[4]);
        BE::write_u32(&mut output[20..24], self.state[5]);
        BE::write_u32(&mut output[24..28], self.state[6]);
        BE::write_u32(&mut output[28..32], self.state[7]);

        output
    }

    pub fn oneshot<T: AsRef<[u8]>>(data: T) -> [u8; DIGEST_LEN] {
        let mut m = Self::new();
        m.update(data.as_ref());
        m.finalize();
        m.output()
    }
}

pub fn sha256<T: AsRef<[u8]>>(data: T) -> [u8; DIGEST_LEN] {
    Sha256::oneshot(data)
}



#[cfg(test)]
#[bench]
fn bench_sha256_transform_generic(b: &mut test::Bencher) {
    // test pure::bench_sha256_sd_64_bytes ... bench:         315 ns/iter (+/- 42) = 203 MB/s
    // test sha2::bench_sha256_sd_64_bytes ... bench:         398 ns/iter (+/- 58) = 160 MB/s
    // test sha2::bench_sha256_sd_64_bytes ... bench:         363 ns/iter (+/- 53) = 176 MB/s
    let data = [0u8; 64];
    b.bytes = data.len() as u64;
    b.iter(|| {
        let mut state = INITIAL_STATE;
        sha256_transform_generic(&mut state, &data[..]);
        state
    });
}

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sha"))]
#[cfg(test)]
#[bench]
fn bench_sha256_transform_shani(b: &mut test::Bencher) {
    let data = [0u8; 64];
    b.bytes = data.len() as u64;
    b.iter(|| {
        let mut state = INITIAL_STATE;
        sha256_transform_shani(&mut state, &data[..]);
        state
    });
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon", target_feature = "crypto"))]
#[cfg(test)]
#[bench]
fn bench_sha256_transform_neon(b: &mut test::Bencher) {
    let data = [0u8; 64];
    b.bytes = data.len() as u64;
    b.iter(|| {
        let mut state = INITIAL_STATE;
        sha256_transform_neon(&mut state, &data[..]);
        state
    });
}

#[test]
fn test_sha256_one_block_message() {
    let msg = b"abc";
    let digest = [
        186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35, 
        176, 3, 97, 163, 150, 23, 122, 156, 180, 16, 255, 97, 242, 0, 21, 173,
    ];
    assert_eq!(Sha256::oneshot(&msg), digest);
}
#[test]
fn test_sha256_multi_block_message() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let digest = [
        36, 141, 106, 97, 210, 6, 56, 184, 229, 192, 38, 147, 12, 62, 96, 57, 
        163, 60, 228, 89, 100, 255, 33, 103, 246, 236, 237, 212, 25, 219, 6, 193,
    ];
    assert_eq!(Sha256::oneshot(&msg[..]), digest);
}
#[test]
fn test_sha256_long_message() {
    let msg = vec![b'a'; 1000_000];
    let digest = [
        205, 199, 110, 92, 153, 20, 251, 146, 129, 161, 199, 226, 132, 215, 62, 
        103, 241, 128, 154, 72, 164, 151, 32, 14, 4, 109, 57, 204, 199, 17, 44, 208,
    ];
    assert_eq!(Sha256::oneshot(&msg), digest);
}

#[test]
fn test_sha256_transform_block() {
    let mut state = INITIAL_STATE;
    let data = [0u8; 64];

    sha256_transform(&mut state, &data);
    assert_eq!(state, [3663108286, 398046313, 1647531929, 2006957770, 2363872401, 3235013187, 3137272298, 406301144]);
}