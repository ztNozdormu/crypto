// Recommendation for Block Cipher Modes of Operation:  Galois/Counter Mode (GCM) and GMAC
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// 
// Galois/Counter Mode:
// https://en.wikipedia.org/wiki/Galois/Counter_Mode
// 
// NOTE: 
//      1. GCM 认证算法本身支持变长的 IV，但是目前普遍的实现都是限制 IV 长度至 12 Bytes。
//      2. GCM 只可以和 块大小为 16 Bytes 的块密码算法协同工作。
// 

use crate::aes::generic::ExpandedKey128;

use subtle;


const BLOCK_LEN: usize = 16;
const TAG_LEN: usize   = 16; // 16-Bytes, 128-Bits
const IV_LEN: usize    = 12; // 12-Bytes,  96-Bits
// Reduction table
// 
// Shoup's method for multiplication use this table with
//     last4[x] = x times P^128
// where x and last4[x] are seen as elements of GF(2^128) as in [MGV]
const LAST4: [u64; 16] = [
    0x0000, 0x1c20, 0x3840, 0x2460,
    0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560,
    0x9180, 0x8da0, 0xa9c0, 0xb5e0,
];


pub trait BlockCipher {
    const KEY_LEN: usize;
    const BLOCK_LEN: usize;
    
    fn new(key: &[u8]) -> Self;
    fn block_encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]);
    fn block_decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]);
    fn block_encrypt_in_place(&mut self, plaintext_and_ciphertext: &mut [u8]);
    fn block_decrypt_in_place(&mut self, ciphertext_and_plaintext: &mut [u8]);
}

impl BlockCipher for ExpandedKey128 {
    const KEY_LEN: usize   = ExpandedKey128::KEY_LEN;
    const BLOCK_LEN: usize = ExpandedKey128::BLOCK_LEN;
    
    fn new(key: &[u8]) -> Self {
        Self::new(key)
    }

    fn block_encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
        let output = self.encrypt(plaintext);
        ciphertext[..Self::BLOCK_LEN].copy_from_slice(&output);
    }

    fn block_decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) {
        let output = self.decrypt(ciphertext);
        plaintext[..Self::BLOCK_LEN].copy_from_slice(&output);
    }

    fn block_encrypt_in_place(&mut self, plaintext_and_ciphertext: &mut [u8]) {
        let output = self.encrypt(&plaintext_and_ciphertext);
        plaintext_and_ciphertext[..Self::BLOCK_LEN].copy_from_slice(&output);
    }

    fn block_decrypt_in_place(&mut self, ciphertext_and_plaintext: &mut [u8]) {
        let output = self.decrypt(&ciphertext_and_plaintext);
        ciphertext_and_plaintext[..Self::BLOCK_LEN].copy_from_slice(&output);
    }
}



#[inline]
fn gcm_setup_key(key: &[u8], h: &[u8; 16]) -> [[u64; 16]; 2] {
    // NOTE: 参数 h 为 BlockCipherEncrypt([0u8; BlockCipher::BLOCK_LEN])
    assert!(key.len() == 16 || key.len() == 24 || key.len() == 32); // 128, 192, 256
    
    // pack h as two 64-bits ints, big-endian
    let mut vh = u64::from_be_bytes([
        h[0], h[1], h[2], h[3],
        h[4], h[5], h[6], h[7],
    ]);
    let mut vl = u64::from_be_bytes([
        h[ 8], h[ 9], h[10], h[11],
        h[12], h[13], h[14], h[15],
    ]);

    let mut hl = [0u64; 16];
    let mut hh = [0u64; 16];
    
    // 8 = 1000 corresponds to 1 in GF(2^128)
    hl[8] = vl;
    hh[8] = vh;
    
    // TODO: 如果使用 AESNI 里面的 CLMUL 指令的话，
    //       那么下面的代码不再需要。
    let mut i = 4usize;
    while i > 0 {
        // 4, 2, 1
        let t = ( vl & 1 ) * 0xe1000000;
        vl = ( vh << 63 ) | ( vl >> 1 );
        vh = ( vh >> 1 ) ^ (t << 32);

        hl[i] = vl;
        hh[i] = vh;

        i >>= 1;
    }

    i = 2usize;
    while i <= 8 {
        // 2, 4, 8
        vh = hh[i];
        vl = hl[i];
        for j in 1usize..i {
            hh[i + j] = vh ^ hh[j];
            hl[i + j] = vl ^ hl[j];
        }
        i *= 2;
    }

    [hh, hl]
}

// Multiplication operation in GF(2^128)
#[inline]
fn gf_mul(gcm_key: &GcmKey, x: &mut [u8; 16]) {
    let hh = &gcm_key.hh;
    let hl = &gcm_key.hl;

    // TODO: 支持 pclmulqdq 相关的指令。
    //       https://github.com/ARMmbed/mbedtls/blob/development/library/aesni.c#L143
    let mut lo: u8 = x[15] & 0xf;
    let mut hi: u8 = 0;
    let mut zh: u64 = hh[lo as usize];
    let mut zl: u64 = hl[lo as usize];
    let mut rem: u8 = 0;

    for i in 0..16 {
        lo = x[16 - 1 - i] & 0xf;
        hi = (x[16 - 1 - i] >> 4) & 0xf;

        if i != 0 {
            rem = (zl & 0xf) as u8;
            zl = ( zh << 60 ) | ( zl >> 4 );
            zh = zh >> 4;
            zh ^= LAST4[rem as usize] << 48;
            zh ^= hh[lo as usize];
            zl ^= hl[lo as usize];
        }

        rem = (zl & 0xf) as u8;
        zl = ( zh << 60 ) | ( zl >> 4 );
        zh = zh >> 4;

        zh ^= LAST4[rem as usize] << 48;
        zh ^= hh[hi as usize];
        zl ^= hl[hi as usize];
    }

    let a = zh.to_be_bytes();
    let b = zl.to_be_bytes();
    x[0.. 8].copy_from_slice(&a);
    x[8..16].copy_from_slice(&b);
}

#[inline]
fn gcm_hash_aad(gcm_key: &GcmKey, aad: &[u8], buf: &mut [u8; BLOCK_LEN]) {
    for chunk in aad.chunks(BLOCK_LEN) {
        for i in 0..chunk.len() {
            buf[i] ^= chunk[i];
        }
        gf_mul(gcm_key, buf);
    }
}

#[inline]
fn gcm_block_num_inc(nonce: &mut [u8; BLOCK_LEN]) {
    // Counter inc
    for i in 1..5 {
        nonce[16 - i] = nonce[16 - i].wrapping_add(1);
        if nonce[16 - i] != 0 {
            break;
        }
    }
}


#[derive(Debug, Clone)]
pub struct GcmKey {
    hh: [u64; 16],
    hl: [u64; 16],
    nonce: [u8; 16],
}

impl<'a> GcmKey {
    pub fn new(key: &[u8], iv: &[u8], h: &[u8; 16]) -> Self {
        assert_eq!(iv.len(), IV_LEN); // 12 Bytes, 96-Bits

        let [hh, hl] = gcm_setup_key(key, h);

        // NOTE: 前面 12 Byte 为 IV，后面 4 Byte 为 BlockCounter
        let mut nonce = [0u8; IV_LEN + 4];
        nonce[..IV_LEN].copy_from_slice(&iv[..IV_LEN]);
        nonce[15] = 1;

        Self { hh, hl, nonce }
    }
    
    pub fn iv(&self) -> &[u8] {
        &self.nonce[..IV_LEN]
    }

    pub fn counter(&self) -> u32 {
        let a = self.nonce[12];
        let b = self.nonce[13];
        let c = self.nonce[14];
        let d = self.nonce[15];

        u32::from_be_bytes([a, b, c, d])
    }

    pub fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }
}

#[derive(Debug)]
pub struct GcmEncryptor<'c, 'k, C: BlockCipher> {
    cipher: &'c mut C,
    gcm_key: &'k GcmKey,
    // y
    counter_block: [u8; 16],
    // H
    base_ectr: [u8; 16],
    buf: [u8; 16],
    // plaintext length in bytes
    len: u64,
    // Associated Data length in bytes
    aad_len: u64,
}

impl<'c, 'k, C: BlockCipher> GcmEncryptor<'c, 'k, C> {
    pub fn new(cipher: &'c mut C, gcm_key: &'k GcmKey, aad: &[u8]) -> Self {
        debug_assert_eq!(&gcm_key.nonce[12..16], &[0, 0, 0, 1]);
        // NOTE: GCM 只支持 块大小为 16 的密码算法。
        debug_assert_eq!(C::BLOCK_LEN, BLOCK_LEN);

        let mut base_ectr = [0u8; BLOCK_LEN];
        cipher.block_encrypt(&gcm_key.nonce, &mut base_ectr);

        let counter_block = gcm_key.nonce.clone();

        let mut buf = [0u8; 16];
        gcm_hash_aad(gcm_key, aad, &mut buf);

        Self {
            cipher,
            gcm_key,
            counter_block,
            base_ectr,
            buf, 
            len: 0,
            aad_len: aad.len() as u64,
        }
    }

    pub fn update(&mut self, plaintext_data: &[u8], ciphertext: &mut [u8]) {
        self.len += plaintext_data.len() as u64;

        for (block_index, plaintext) in plaintext_data.chunks(BLOCK_LEN).enumerate() {
            gcm_block_num_inc(&mut self.counter_block);

            let mut ectr = [0u8; BLOCK_LEN];
            self.cipher.block_encrypt(&self.counter_block, &mut ectr);

            for i in 0..plaintext.len() {
                ciphertext[block_index * BLOCK_LEN + i] = ectr[i] ^ plaintext[i];
                self.buf[i] ^= ciphertext[block_index * BLOCK_LEN + i];
            }

            gf_mul(&self.gcm_key, &mut self.buf);
        }
    }

    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        let data_len_bits: u64 = self.len * 8;
        let aad_len_bits: u64  = self.aad_len * 8;
        
        let mut octets = [0u8; 16];
        let mut tag  = self.base_ectr;

        octets[0.. 8].copy_from_slice(&aad_len_bits.to_be_bytes());
        octets[8..16].copy_from_slice(&data_len_bits.to_be_bytes());

        for i in 0..BLOCK_LEN {
            self.buf[i] ^= octets[i];
        }

        gf_mul(&self.gcm_key, &mut self.buf);

        for i in 0..TAG_LEN {
            tag[i] ^= self.buf[i];
        }

        tag
    }
}


#[derive(Debug, Clone)]
pub struct AesGcm128 {
    cipher: ExpandedKey128,
    gcm_key: GcmKey,
    aad: Vec<u8>,
    // base_ectr: [u8; 16],
    // ectr: [u8; 16],
}

// 6.  AES GCM Algorithms for Secure Shell
// https://tools.ietf.org/html/rfc5647#section-6
impl AesGcm128 {
    pub const BLOCK_LEN: usize = ExpandedKey128::BLOCK_LEN;
    pub const TAG_LEN: usize   = TAG_LEN;
    pub const IV_LEN: usize    = IV_LEN;
    pub const NONCE_LEN: usize = IV_LEN + 4;

    pub fn new(key: &[u8], iv: &[u8], aad: &[u8]) -> Self {
        assert!(key.len() == 16 || key.len() == 24 || key.len() == 32); // 128, 192, 256
        assert_eq!(iv.len(), Self::IV_LEN); // 96-Bits
        // NOTE: 实际上 GCM 允许的 aad 数据的长度 是 2**61 Bytes。
        assert!(aad.len() <= 1024);
        
        let cipher = ExpandedKey128::new(key);
        let zeros = [0u8; Self::BLOCK_LEN];
        let h = cipher.encrypt(&zeros);
        let gcm_key = GcmKey::new(key, iv, &h);

        let aad = aad.to_vec();

        Self { cipher, gcm_key, aad }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8; Self::TAG_LEN]) {
        debug_assert_eq!(plaintext.len(), ciphertext.len());
        debug_assert_eq!(tag.len(), Self::TAG_LEN);

        let mut gcm_encryptor = GcmEncryptor::new(&mut self.cipher, &self.gcm_key, &self.aad);
        gcm_encryptor.update(plaintext, ciphertext);
        tag.copy_from_slice(&gcm_encryptor.finalize());
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], input_tag: &[u8; Self::TAG_LEN], plaintext: &mut [u8]) -> bool {
        debug_assert_eq!(plaintext.len(), ciphertext.len());
        debug_assert_eq!(input_tag.len(), Self::TAG_LEN);
        debug_assert_eq!(&self.gcm_key.nonce[12..16], &[0, 0, 0, 1]);

        // Start
        let base_ectr = self.cipher.encrypt(&self.gcm_key.nonce);
        let mut counter_block = self.gcm_key.nonce.clone();
        let mut buf = [0u8; 16];
        gcm_hash_aad(&self.gcm_key, &self.aad, &mut buf);

        // Update
        let mut len = 0u64;
        let aad_len = self.aad.len() as u64;

        let ciphertext_data = ciphertext;
        len += ciphertext_data.len() as u64;

        for (block_index, ciphertext) in ciphertext_data.chunks(BLOCK_LEN).enumerate() {
            gcm_block_num_inc(&mut counter_block);

            let ectr = self.cipher.encrypt(&counter_block);

            for i in 0..ciphertext.len() {
                buf[i] ^= ciphertext[i];

                plaintext[block_index * BLOCK_LEN + i] = ectr[i] ^ ciphertext[i];
            }

            gf_mul(&self.gcm_key, &mut buf);
        }


        // finalize
        let data_len_bits: u64 = len * 8;
        let aad_len_bits: u64  = aad_len * 8;
        
        let mut octets = [0u8; 16];
        let mut tag  = base_ectr;

        octets[0.. 8].copy_from_slice(&data_len_bits.to_le_bytes());
        octets[8..16].copy_from_slice(&aad_len_bits.to_le_bytes());

        for i in 0..BLOCK_LEN {
            buf[i] ^= octets[i];
        }

        gf_mul(&self.gcm_key, &mut buf);

        for i in 0..TAG_LEN {
            tag[i] ^= buf[i];
        }

        // Verify
        bool::from(subtle::ConstantTimeEq::ct_eq(&input_tag[..], &tag))
    }
}


#[test]
fn test_aes_128_gcm() {
    // B   AES Test Vectors, (Page-29)
    // https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

    // Test  Case  1
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let iv = hex::decode("000000000000000000000000").unwrap();
    let aad = [0u8; 0];
    let plaintext = [0u8; 0];
    let mut ciphertext = plaintext.clone();
    let mut tag = [0u8; TAG_LEN];

    let mut cipher = AesGcm128::new(&key, &iv, &aad);
    cipher.encrypt(&plaintext, &mut ciphertext, &mut tag);
    assert_eq!(&ciphertext[..], &[]);
    assert_eq!(&tag[..], &hex::decode("58e2fccefa7e3061367f1d57a4e7455a").unwrap()[..]);


    // Test  Case  2
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let iv = hex::decode("000000000000000000000000").unwrap();
    let aad = [0u8; 0];
    let plaintext = hex::decode("00000000000000000000000000000000").unwrap();
    let mut ciphertext = plaintext.clone();
    let mut tag = [0u8; TAG_LEN];

    let mut cipher = AesGcm128::new(&key, &iv, &aad);
    cipher.encrypt(&plaintext, &mut ciphertext, &mut tag);
    assert_eq!(&ciphertext[..], &hex::decode("0388dace60b6a392f328c2b971b2fe78").unwrap()[..]);
    assert_eq!(&tag[..], &hex::decode("ab6e47d42cec13bdf53a67b21257bddf").unwrap()[..]);


    // Test  Case  3
    let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
    let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];
    let plaintext = hex::decode("d9313225f88406e5a55909c5aff5269a\
86a7a9531534f7da2e4c303d8a318a72\
1c3c0c95956809532fcf0e2449a6b525\
b16aedf5aa0de657ba637b391aafd255").unwrap();
    let mut ciphertext = plaintext.clone();
    let mut tag = [0u8; TAG_LEN];

    let mut cipher = AesGcm128::new(&key, &iv, &aad);
    cipher.encrypt(&plaintext, &mut ciphertext, &mut tag);
    assert_eq!(&ciphertext[..], &hex::decode("42831ec2217774244b7221b784d0d49c\
e3aa212f2c02a4e035c17e2329aca12e\
21d514b25466931c7d8f6a5aac84aa05\
1ba30b396a0aac973d58e091473f5985").unwrap()[..]);
    assert_eq!(&tag[..], &hex::decode("4d5c2af327cd64a62cf35abd2ba6fab4").unwrap()[..]);


    // Test  Case  4
    let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
    let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeef\
abaddad2").unwrap();
    let plaintext = hex::decode("d9313225f88406e5a55909c5aff5269a\
86a7a9531534f7da2e4c303d8a318a72\
1c3c0c95956809532fcf0e2449a6b525\
b16aedf5aa0de657ba637b39").unwrap();
    let mut ciphertext = plaintext.clone();
    let mut tag = [0u8; TAG_LEN];

    let mut cipher = AesGcm128::new(&key, &iv, &aad);
    cipher.encrypt(&plaintext, &mut ciphertext, &mut tag);
    assert_eq!(&ciphertext[..], &hex::decode("42831ec2217774244b7221b784d0d49c\
e3aa212f2c02a4e035c17e2329aca12e\
21d514b25466931c7d8f6a5aac84aa05\
1ba30b396a0aac973d58e091").unwrap()[..]);
    assert_eq!(&tag[..], &hex::decode("5bc94fbc3221a5db94fae95ae7121a47").unwrap()[..]);
}
