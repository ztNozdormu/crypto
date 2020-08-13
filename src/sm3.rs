
// 代码参考:
// https://github.com/citahub/libsm/blob/master/src/sm3/hash.rs

pub const BLOCK_LEN: usize  = 64;
pub const DIGEST_LEN: usize = 32;

pub const INITIAL_STATE: [u32; 8] = [
    0x7380_166f, 0x4914_b2b9, 0x1724_42d7, 0xda8a_0600, 
    0xa96f_30bc, 0x1631_38aa, 0xe38d_ee4d, 0xb0fb_0e4e, 
];


#[inline(always)]
fn ff0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn ff1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

#[inline(always)]
fn gg0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn gg1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[inline(always)]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

#[inline(always)]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}


#[derive(Debug, Clone)]
pub struct Sm3 {
    digest: [u32; 8],
    length: u64,
    unhandle_msg: Vec<u8>,
}

impl Sm3 {
    pub fn new(data: &[u8]) -> Self {
        let mut hash = Self {
            digest: INITIAL_STATE,
            length: (data.len() << 3) as u64,
            unhandle_msg: Vec::new(),
        };
        for i in data.iter() {
            hash.unhandle_msg.push(*i);
        }
        hash
    }

    pub fn get_hash(&mut self) -> [u8; DIGEST_LEN] {
        self.pad();

        let mut output: [u8; DIGEST_LEN] = [0u8; DIGEST_LEN];
        let len = self.unhandle_msg.len();
        let mut count: usize = 0;
        let mut buffer: [u8; 64] = [0; 64];

        while count * 64 != len {
            for i in (count * 64)..(count * 64 + 64) {
                buffer[i - count * 64] = self.unhandle_msg[i];
            }
            self.update(&buffer);
            count += 1;
        }

        for i in 0..8 {
            let start = i * 4;
            let end = start + 4;
            output[start..end].copy_from_slice(&self.digest[i].to_be_bytes());
        }

        output
    }

    fn pad(&mut self) {
        self.unhandle_msg.push(0x80);
        let blocksize = 64;
        while self.unhandle_msg.len() % blocksize != 56 {
            self.unhandle_msg.push(0x00);
        }

        self.unhandle_msg.push((self.length >> 56 & 0xff) as u8);
        self.unhandle_msg.push((self.length >> 48 & 0xff) as u8);
        self.unhandle_msg.push((self.length >> 40 & 0xff) as u8);
        self.unhandle_msg.push((self.length >> 32 & 0xff) as u8);
        self.unhandle_msg.push((self.length >> 24 & 0xff) as u8);
        self.unhandle_msg.push((self.length >> 16 & 0xff) as u8);
        self.unhandle_msg.push((self.length >> 8 & 0xff) as u8);
        self.unhandle_msg.push((self.length & 0xff) as u8);

        if self.unhandle_msg.len() % 64 != 0 {
            panic!("-------SM3 Pad: error msgLen ------");
        }
    }

    fn update(&mut self, buffer: &[u8; 64]) {
        //get expend
        let mut w: [u32; 68]  = [0; 68];
        let mut w1: [u32; 64] = [0; 64];

        for i in 0..16 {
            let a = buffer[i * 4 + 0];
            let b = buffer[i * 4 + 1];
            let c = buffer[i * 4 + 2];
            let d = buffer[i * 4 + 3];
            w[i] = u32::from_be_bytes([a, b, c, d]);
        }

        for i in 16..68 {
            w[i] = p1(w[i - 16] ^ w[i - 9] ^ w[i - 3].rotate_left(15))
                ^ w[i - 13].rotate_left(7)
                ^ w[i - 6];
        }

        for i in 0..BLOCK_LEN {
            w1[i] = w[i] ^ w[i + 4];
        }

        let mut ra = self.digest[0];
        let mut rb = self.digest[1];
        let mut rc = self.digest[2];
        let mut rd = self.digest[3];
        let mut re = self.digest[4];
        let mut rf = self.digest[5];
        let mut rg = self.digest[6];
        let mut rh = self.digest[7];
        let mut ss1: u32;
        let mut ss2: u32;
        let mut tt1: u32;
        let mut tt2: u32;

        for i in 0..16 {
            ss1 = ra
                .rotate_left(12)
                .wrapping_add(re)
                .wrapping_add(0x79cc_4519u32.rotate_left(i as u32))
                .rotate_left(7);
            ss2 = ss1 ^ ra.rotate_left(12);
            tt1 = ff0(ra, rb, rc)
                .wrapping_add(rd)
                .wrapping_add(ss2)
                .wrapping_add(w1[i]);
            tt2 = gg0(re, rf, rg)
                .wrapping_add(rh)
                .wrapping_add(ss1)
                .wrapping_add(w[i]);
            rd = rc;
            rc = rb.rotate_left(9);
            rb = ra;
            ra = tt1;
            rh = rg;
            rg = rf.rotate_left(19);
            rf = re;
            re = p0(tt2);
        }

        for i in 16..64 {
            ss1 = ra
                .rotate_left(12)
                .wrapping_add(re)
                .wrapping_add(0x7a87_9d8au32.rotate_left(i as u32))
                .rotate_left(7);
            ss2 = ss1 ^ ra.rotate_left(12);
            tt1 = ff1(ra, rb, rc)
                .wrapping_add(rd)
                .wrapping_add(ss2)
                .wrapping_add(w1[i]);
            tt2 = gg1(re, rf, rg)
                .wrapping_add(rh)
                .wrapping_add(ss1)
                .wrapping_add(w[i]);
            rd = rc;
            rc = rb.rotate_left(9);
            rb = ra;
            ra = tt1;
            rh = rg;
            rg = rf.rotate_left(19);
            rf = re;
            re = p0(tt2);
        }

        self.digest[0] ^= ra;
        self.digest[1] ^= rb;
        self.digest[2] ^= rc;
        self.digest[3] ^= rd;
        self.digest[4] ^= re;
        self.digest[5] ^= rf;
        self.digest[6] ^= rg;
        self.digest[7] ^= rh;
    }
}


//
// Sample 1
// Input:"abc"
// Output:66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0

// Sample 2
// Input:"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
// Outpuf:debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732
#[test]
fn lets_hash_1() {
    let mut sm3 = Sm3::new(b"abc");
    let digest = sm3.get_hash();

    assert_eq!(&digest[..], &[
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 
        0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2, 
        0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 
        0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0, 
    ]);
}

#[test]
fn lets_hash_2() {
    let mut sm3 = Sm3::new(b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
    let digest = sm3.get_hash();
    
    assert_eq!(&digest[..], &[
        0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 
        0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d, 
        0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 
        0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32, 
    ]);
}
