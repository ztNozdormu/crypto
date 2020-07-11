// 2.5.  The Poly1305 Algorithm
// https://tools.ietf.org/html/rfc8439#section-2.5
// 
//    Poly1305 is a one-time authenticator designed by D. J. Bernstein.
//    Poly1305 takes a 32-byte one-time key and a message and produces a
//    16-byte tag.  This tag is used to authenticate the message.
// 
// The Poly1305-AES message-authenticationcode
// http://cr.yp.to/mac/poly1305-20050329.pdf
// 
// 参考实现代码:
// https://github.com/floodyberry/poly1305-donna/blob/master/poly1305-donna-32.h
// 
// Poly1305-AES speed tables
// https://cr.yp.to/mac/speed.html

// 
// TODO: 
//      `r` 和 `s` 里面用到的 fixed-size bignum 有时间重新写。
// 

use byteorder::{LE, ByteOrder};


pub const POLY1305_KEY_LEN: usize   = 32;
pub const POLY1305_BLOCK_LEN: usize = 16;
pub const POLY1305_TAG_LEN: usize   = 16; // Mac


// 2.5.1.  The Poly1305 Algorithms in Pseudocode
// https://tools.ietf.org/html/rfc8439#section-2.5.1
#[derive(Debug, Clone)]
pub struct Poly1305 {
    r        : [u32; 5], // r: le_bytes_to_num(key[0..15])
    h        : [u32; 5],
    pad      : [u32; 4], // s: le_bytes_to_num(key[16..31])
    leftover : usize,
    buffer   : [u8; POLY1305_BLOCK_LEN],
    finalized: bool,
}

impl Default for Poly1305 {
    fn default() -> Self {
        Self {
            r  : [0u32; 5],
            h  : [0u32; 5],
            pad: [0u32; 4],
            leftover: 0usize,
            buffer: [0u8; 16],
            finalized: false,
        }
    }
}

impl Poly1305 {
    pub fn new(key: &[u8]) -> Poly1305 {
        // A 256-bit one-time key
        debug_assert!(key.len() >= POLY1305_KEY_LEN);
        let mut poly = Poly1305::default();

        // r &= 0xffffffc0ffffffc0ffffffc0fffffff
        poly.r[0] =  LE::read_u32(&key[ 0.. 4])       & 0x3ffffff;
        poly.r[1] = (LE::read_u32(&key[ 3.. 7]) >> 2) & 0x3ffff03;
        poly.r[2] = (LE::read_u32(&key[ 6..10]) >> 4) & 0x3ffc0ff;
        poly.r[3] = (LE::read_u32(&key[ 9..13]) >> 6) & 0x3f03fff;
        poly.r[4] = (LE::read_u32(&key[12..16]) >> 8) & 0x00fffff;

        // save pad for later
        poly.pad[0] = LE::read_u32(&key[16..20]);
        poly.pad[1] = LE::read_u32(&key[20..24]);
        poly.pad[2] = LE::read_u32(&key[24..28]);
        poly.pad[3] = LE::read_u32(&key[28..32]);

        poly
    }

    pub fn r(&self) -> &[u32; 5] {
        &self.r
    }

    pub fn s(&self) -> &[u32; 4] {
        &self.pad
    }

    pub fn block(&mut self, m: &[u8]) {
        debug_assert_eq!(m.len(), POLY1305_BLOCK_LEN);

        let hibit : u32 = if self.finalized { 0 } else { 1 << 24 };

        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        // h += m
        h0 += (LE::read_u32(&m[0..4])       ) & 0x3ffffff;
        h1 += (LE::read_u32(&m[3..7])   >> 2) & 0x3ffffff;
        h2 += (LE::read_u32(&m[6..10])  >> 4) & 0x3ffffff;
        h3 += (LE::read_u32(&m[9..13])  >> 6) & 0x3ffffff;
        h4 += (LE::read_u32(&m[12..16]) >> 8) | hibit;

        // h *= r
        let     d0 = (h0 as u64 * r0 as u64) 
                   + (h1 as u64 * s4 as u64) 
                   + (h2 as u64 * s3 as u64) 
                   + (h3 as u64 * s2 as u64) 
                   + (h4 as u64 * s1 as u64);
        let mut d1 = (h0 as u64 * r1 as u64) 
                   + (h1 as u64 * r0 as u64) 
                   + (h2 as u64 * s4 as u64) 
                   + (h3 as u64 * s3 as u64) 
                   + (h4 as u64 * s2 as u64);
        let mut d2 = (h0 as u64 * r2 as u64) 
                   + (h1 as u64 * r1 as u64) 
                   + (h2 as u64 * r0 as u64) 
                   + (h3 as u64 * s4 as u64) 
                   + (h4 as u64 * s3 as u64);
        let mut d3 = (h0 as u64 * r3 as u64) 
                   + (h1 as u64 * r2 as u64) 
                   + (h2 as u64 * r1 as u64) 
                   + (h3 as u64 * r0 as u64) 
                   + (h4 as u64 * s4 as u64);
        let mut d4 = (h0 as u64 * r4 as u64) 
                   + (h1 as u64 * r3 as u64) 
                   + (h2 as u64 * r2 as u64) 
                   + (h3 as u64 * r1 as u64) 
                   + (h4 as u64 * r0 as u64);

        // (partial) h %= p
        let mut c : u32;
                        c = (d0 >> 26) as u32; h0 = d0 as u32 & 0x3ffffff;
        d1 += c as u64; c = (d1 >> 26) as u32; h1 = d1 as u32 & 0x3ffffff;
        d2 += c as u64; c = (d2 >> 26) as u32; h2 = d2 as u32 & 0x3ffffff;
        d3 += c as u64; c = (d3 >> 26) as u32; h3 = d3 as u32 & 0x3ffffff;
        d4 += c as u64; c = (d4 >> 26) as u32; h4 = d4 as u32 & 0x3ffffff;
        h0 += c * 5;    c = h0 >> 26; h0 = h0 & 0x3ffffff;
        h1 += c;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
        self.h[4] = h4;
    }

    pub fn input(&mut self, data: &[u8]) {
        debug_assert!(!self.finalized);
        let mut m = data;

        if self.leftover > 0 {
            let want = std::cmp::min(16 - self.leftover, m.len());
            for i in 0..want {
                self.buffer[self.leftover+i] = m[i];
            }
            m = &m[want..];
            self.leftover += want;

            if self.leftover < 16 {
                return;
            }

            // self.block(self.buffer[..]);
            let tmp = self.buffer;
            self.block(&tmp);

            self.leftover = 0;
        }

        while m.len() >= 16 {
            self.block(&m[0..16]);
            m = &m[16..];
        }

        for i in 0..m.len() {
            self.buffer[i] = m[i];
        }
        self.leftover = m.len();
    }

    pub fn finish(&mut self) {
        if self.leftover > 0 {
            self.buffer[self.leftover] = 1;
            for i in self.leftover+1..16 {
                self.buffer[i] = 0;
            }
            self.finalized = true;
            let tmp = self.buffer;
            self.block(&tmp);
        }

        // fully carry h
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        let mut c : u32;
                     c = h1 >> 26; h1 = h1 & 0x3ffffff;
        h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
        h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
        h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
        h1 +=     c;

        // compute h + -p
        let mut g0 = h0.wrapping_add(5); c = g0 >> 26; g0 &= 0x3ffffff;
        let mut g1 = h1.wrapping_add(c); c = g1 >> 26; g1 &= 0x3ffffff;
        let mut g2 = h2.wrapping_add(c); c = g2 >> 26; g2 &= 0x3ffffff;
        let mut g3 = h3.wrapping_add(c); c = g3 >> 26; g3 &= 0x3ffffff;
        let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // select h if h < p, or h + -p if h >= p
        let mut mask = (g4 >> (32 - 1)).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // h = h % (2^128)
        h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
        h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
        h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
        h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

        // h = mac = (h + pad) % (2^128)
        let mut f : u64;
        f = h0 as u64 + self.pad[0] as u64            ; h0 = f as u32;
        f = h1 as u64 + self.pad[1] as u64 + (f >> 32); h1 = f as u32;
        f = h2 as u64 + self.pad[2] as u64 + (f >> 32); h2 = f as u32;
        f = h3 as u64 + self.pad[3] as u64 + (f >> 32); h3 = f as u32;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
    }

    pub fn state(&self) -> &[u32; 5] {
        &self.h
    }

    pub fn mac(&mut self) -> [u8; POLY1305_TAG_LEN] {
        if !self.finalized{
            self.finish();
        }

        // The output is a 128-bit tag.
        let mut mac = [0u8; POLY1305_TAG_LEN];
        LE::write_u32(&mut mac[ 0.. 4], self.h[0]);
        LE::write_u32(&mut mac[ 4.. 8], self.h[1]);
        LE::write_u32(&mut mac[ 8..12], self.h[2]);
        LE::write_u32(&mut mac[12..16], self.h[3]);
        mac
    }
}


#[test]
fn test_poly1305_donna() {
    // https://github.com/floodyberry/poly1305-donna/blob/master/example-poly1305.c
    let expected: [u8; POLY1305_TAG_LEN] = [
        0xdd, 0xb9, 0xda, 0x7d, 0xdd, 0x5e, 0x52, 0x79, 
        0x27, 0x30, 0xed, 0x5c, 0xda, 0x5f, 0x90, 0xa4
    ];
    let mut key = [0u8; POLY1305_KEY_LEN];
    let mut msg = [0u8; 73];
    
    for i in 0..key.len() {
        key[i] = i as u8 + 221;
    }
    for i in 0..msg.len() {
        msg[i] = i as u8 + 121;
    }

    let mut poly1305 = Poly1305::new(&key);
    poly1305.input(&msg);

    assert_eq!(poly1305.mac(), expected);
}

#[test]
fn test_poly1305() {
    // 2.5.2.  Poly1305 Example and Test Vector
    // https://tools.ietf.org/html/rfc8439#section-2.5.2
    let key = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8, 
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    ];
    let message: &[u8] = b"Cryptographic Forum Research Group";
    let expected_tag = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    ];

    let mut poly1305 = Poly1305::new(&key);
    poly1305.input(message);
    assert_eq!(&poly1305.mac(), &expected_tag);

    poly1305.mac();
    poly1305.mac();
    poly1305.mac();
    poly1305.mac();
}


