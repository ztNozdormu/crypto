// AES-GCM-SIV: Specification and Analysis
// https://eprint.iacr.org/2017/168.pdf
// 
// AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption
// https://tools.ietf.org/html/rfc8452
use crate::aes::Aes128;

use subtle;


// Carry-less Multiplication
#[inline]
fn cl_mul(a: u64, b: u64, dst: &mut [u64; 2]) {
    for i in 0..64 {
        if (b & (1 << i)) == 1 {
            dst[1] ^= a;
        }

        // Shift the result
        dst[0] >>= 1;

        if (dst[1] & (1 << 0)) == 1 {
            dst[0] ^= 1 << 63;
        }

        dst[1] >>= 1;
    }
}

#[derive(Debug, Clone)]
pub struct Polyval {
    key: [u8; 16],
    h: [u8; 16],
}

impl Polyval {
    pub const KEY_LEN: usize    = 16;
    pub const OUTPUT_LEN: usize = 16;

    pub fn new(k: &[u8]) -> Self {
        assert_eq!(k.len(), Self::KEY_LEN);

        let h = [0u8; Self::OUTPUT_LEN];
        let mut key = [0u8; Self::KEY_LEN];
        key.copy_from_slice(k);

        Self { key, h  }
    }

    #[inline]
    pub fn reset(&mut self) {
        self.h = [0u8; 16];
    }

    fn gf_mul(&mut self) {
        // a: h
        // b: key
        let a = [
            u64::from_ne_bytes([
                self.h[0], self.h[1], self.h[2], self.h[3],
                self.h[4], self.h[5], self.h[6], self.h[7],
            ]),
            u64::from_ne_bytes([
                self.h[ 8], self.h[ 9], self.h[10], self.h[11],
                self.h[12], self.h[13], self.h[14], self.h[15],
            ]),
        ];

        let b = [
            u64::from_ne_bytes([
                self.key[0], self.key[1], self.key[2], self.key[3],
                self.key[4], self.key[5], self.key[6], self.key[7],
            ]),
            u64::from_ne_bytes([
                self.key[ 8], self.key[ 9], self.key[10], self.key[11],
                self.key[12], self.key[13], self.key[14], self.key[15],
            ]),
        ];

        let mut tmp1 = [0u64; 2];
        let mut tmp2 = [0u64; 2];
        let mut tmp3 = [0u64; 2];
        let mut tmp4 = [0u64; 2];

        cl_mul(a[0], b[0], &mut tmp1); // 0x00
        cl_mul(a[1], b[0], &mut tmp2); // 0x01
        cl_mul(a[0], b[1], &mut tmp3); // 0x10
        cl_mul(a[1], b[1], &mut tmp4); // 0x11

        tmp2[0] ^= tmp3[0];
        tmp2[1] ^= tmp3[1];

        tmp3[0] = 0;
        tmp3[1] = tmp2[0];
        
        tmp2[0] = tmp2[1];
        tmp2[1] = 0;
        
        tmp1[0] ^= tmp3[0];
        tmp1[1] ^= tmp3[1];
        
        tmp4[0] ^= tmp2[0];
        tmp4[1] ^= tmp2[1];
        
        const XMMMASK: [u64; 2] = [0x1u64; 0xc200000000000000];

        cl_mul(XMMMASK[1], tmp1[0], &mut tmp2); // 0x01

        unsafe {
            let tmp33 = std::mem::transmute::<&mut [u64; 2], &mut [u32; 4]>(&mut tmp3);
            let tmp11 = std::mem::transmute::<&mut [u64; 2], &mut [u32; 4]>(&mut tmp1);

            tmp33[0] = tmp11[2];
            tmp33[1] = tmp11[3];
            tmp33[2] = tmp11[0];
            tmp33[3] = tmp11[1];
        }
        
        tmp1[0] = tmp2[0] ^ tmp3[0];
        tmp1[1] = tmp2[1] ^ tmp3[1];

        cl_mul(XMMMASK[1], tmp1[0], &mut tmp2); // 0x01

        unsafe {
            let tmp33 = std::mem::transmute::<&mut [u64; 2], &mut [u32; 4]>(&mut tmp3);
            let tmp11 = std::mem::transmute::<&mut [u64; 2], &mut [u32; 4]>(&mut tmp1);

            tmp33[0] = tmp11[2];
            tmp33[1] = tmp11[3];
            tmp33[2] = tmp11[0];
            tmp33[3] = tmp11[1];
        }

        tmp1[0] = tmp2[0] ^ tmp3[0];
        tmp1[1] = tmp2[1] ^ tmp3[1];
        
        tmp4[0] ^= tmp1[0];
        tmp4[1] ^= tmp1[1];

        self.h[0.. 8].copy_from_slice(&tmp4[0].to_ne_bytes());
        self.h[8..16].copy_from_slice(&tmp4[1].to_ne_bytes());
    }

    pub fn polyval(&mut self, data: &[u8]) {
        // void POLYVAL(uint64_t* input, uint64_t* H, uint64_t len, uint64_t* result) {
        let mut block_idx: usize = 0usize;
        for chunk in data.chunks_exact(16) {
            for i in 0..16 {
                self.h[i] ^= chunk[i];
            }
            // gfmul_int(current_res, H, current_res);
            self.gf_mul();

            block_idx += 1;
        }

        let remainder_len = data.len() - block_idx * 16 - 16;
        if remainder_len > 0 {
            // padding
            let mut block = [0u8; 16];
            let offset = block_idx * 16;
            let remainder = &data[offset..];
            block[..remainder.len()].copy_from_slice(remainder);

            for i in 0..16 {
                self.h[i] ^= block[i];
            }
            // gfmul_int(current_res, H, current_res);
            self.gf_mul();
        }
    }
}

fn incr(block: &mut [u8]) {
    debug_assert_eq!(block.len(), 16);

    let counter = u32::from_le_bytes([block[0], block[1], block[2], block[3]]).wrapping_add(1).to_le_bytes();
    block[0] = counter[0];
    block[1] = counter[1];
    block[2] = counter[2];
    block[3] = counter[3];
}

// AEAD_AES_128_GCM_SIV
// P_MAX is 2^36, 
// A_MAX is 2^36, 
// N_MIN and N_MAX are 12, 
// C_MAX is 2^36 + 16

// AEAD_AES_256_GCM_SIV
// K_LEN is 32, 
// P_MAX is 2^36, 
// A_MAX is 2^36, 
// N_MIN and N_MAX are 12,
// C_MAX is 2^36 + 16


// AEAD_AES_128_GCM_SIV
#[derive(Debug, Clone)]
pub struct Aes128GcmSiv {
    cipher: Aes128,
    nonce: [0u8; Self::NONCE_LEN],
    polyval: Polyval,
}

impl Aes128GcmSiv {
    pub const KEY_LEN: usize   = Aes128::KEY_LEN;
    pub const BLOCK_LEN: usize = Aes128::BLOCK_LEN;
    pub const TAG_LEN: usize   = Aes128::BLOCK_LEN;
    pub const NONCE_LEN: usize = 12;

    pub const P_MAX: usize = 68719476736;                 // 2^36
    pub const A_MAX: usize = 68719476736;                 // 2^36
    pub const C_MAX: usize = 68719476736 + Self::TAG_LEN; // 2^36 + 16

    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        assert_eq!(nonce.len(), Self::NONCE_LEN); // 96-Bits
        assert_eq!(Self::BLOCK_LEN, 16);
        // NOTE: GCM-SIV 并不支持和 AES192 算法进行搭配。
        assert!(Self::KEY_LEN == 16 || Self::KEY_LEN == 32);

        let cipher = Aes128::new(key);
        
        let mut counter_block = [0u8; Self::BLOCK_LEN];
        counter_block[4..16].copy_from_slice(nonce);

        // message_authentication_key
        let mut ak = [0u8; Self::BLOCK_LEN];
        // message_encryption_key
        let mut ek = [0u8; Self::KEY_LEN];

        let mut tmp = counter_block.clone();
        tmp[0] = 0;
        cipher.encrypt(&mut tmp);
        ak[0..8].copy_from_slice(&tmp[0..8]);

        tmp = counter_block.clone();
        tmp[0] = 1;
        cipher.encrypt(&mut tmp);
        ak[8..16].copy_from_slice(&tmp[0..8]);

        tmp = counter_block.clone();
        tmp[0] = 2;
        cipher.encrypt(&mut tmp);
        ek[0..8].copy_from_slice(&tmp[0..8]);

        tmp = counter_block.clone();
        tmp[0] = 3;
        cipher.encrypt(&mut tmp);
        ek[8..16].copy_from_slice(&tmp[0..8]);

        // AES-256
        if Self::KEY_LEN == 32 {
            tmp = counter_block.clone();
            tmp[0] = 4;
            cipher.encrypt(&mut tmp);
            ek[16..24].copy_from_slice(&tmp[0..8]);

            tmp = counter_block.clone();
            tmp[0] = 5;
            cipher.encrypt(&mut tmp);
            ek[24..32].copy_from_slice(&tmp[0..8]);
        }

        let cipher = Aes128::new(ek);

        let mut n = [0u8; Self::NONCE_LEN];
        n.copy_from_slice(&nonce[..Self::NONCE_LEN]);
        let nonce = n;

        let polyval = Polyval::new(&ak);

        Self { cipher, nonce, polyval }
    }

    pub fn aead_encrypt(&mut self, aad: &[u8], plaintext_and_ciphertext: &mut [u8]) {
        // 4.  Encryption
        // https://tools.ietf.org/html/rfc8452#section-4
        debug_assert!(aad.len() < Self::A_MAX);
        debug_assert!(plaintext_and_ciphertext.len() < Self::C_MAX);
        debug_assert!(plaintext_and_ciphertext.len() >= Self::TAG_LEN);

        let alen = aad.len();
        let plen = plaintext_and_ciphertext.len() - Self::TAG_LEN;

        let plaintext = &plaintext_and_ciphertext[..plen];

        let mut bit_len_block = [0u8; Self::BLOCK_LEN];
        let aad_bit_len_octets = (alen as u64 * 8).to_le_bytes();
        let plaintext_bit_len_octets = (plen as u64 * 8).to_le_bytes();
        bit_len_block[0.. 8].copy_from_slice(&aad_bit_len_octets);
        bit_len_block[8..16].copy_from_slice(&plaintext_bit_len_octets);

        // void POLYVAL(uint64_t* input, uint64_t* H, uint64_t len, uint64_t* result) {
        self.polyval.reset();

        self.polyval.polyval(aad);
        self.polyval.polyval(plaintext);
        self.polyval.polyval(&bit_len_block);

        for i in 0..Self::NONCE_LEN {
            self.polyval.h[i] ^= self.nonce[i];
        }
        self.polyval.h[15] &= 0x7f;

        // tag = AES(key = message_encryption_key, block = S_s)
        let mut tag = self.polyval.h.clone();
        self.cipher.encrypt(&mut tag);

        // u32 (Counter) || u96 (Nonce)
        let mut counter_block = tag.clone();
        counter_block[15] |= 0x80;

        // CTR
        let plaintext = &mut plaintext_and_ciphertext[..plen];
        for chunk in plaintext.chunks_mut(Self::BLOCK_LEN) {
            incr(&mut counter_block);

            let mut keystream_block = counter_block.clone();
            self.cipher.encrypt(&mut keystream_block);
            for i in 0..chunk.len() {
                chunk[i] ^= keystream_block[i];
            }
        }

        // Save TAG
        &mut plaintext_and_ciphertext[plen..plen + Self::TAG_LEN].copy_from_slice(&tag);
    }

    pub fn aead_decrypt(&mut self, aad: &[u8], ciphertext_and_plaintext: &mut [u8]) {
        debug_assert!(aad.len() < Self::A_MAX);
        debug_assert!(ciphertext_and_plaintext.len() < Self::C_MAX);
        debug_assert!(ciphertext_and_plaintext.len() >= Self::TAG_LEN);

        let alen = aad.len();
        let clen = ciphertext_and_plaintext.len() - Self::TAG_LEN;

        let ciphertext = &ciphertext_and_plaintext[..clen];

        // Input TAG
        let tag1 = &ciphertext_and_plaintext[clen..clen + Self::TAG_LEN];

        let mut counter_block = [0u8; Self::BLOCK_LEN];
        counter_block.copy_from_slice(&tag1);
        counter_block[15] |= 0x80;

        // CTR
        let ciphertext = &mut ciphertext_and_plaintext[..clen];
        for chunk in ciphertext.chunks_mut(Self::BLOCK_LEN) {
            incr(&mut counter_block);

            let mut keystream_block = counter_block.clone();
            self.cipher.encrypt(&mut keystream_block);
            for i in 0..chunk.len() {
                chunk[i] ^= keystream_block[i];
            }
        }

        let cleartext = &ciphertext_and_plaintext[..clen];
        // Auth
        let mut bit_len_block = [0u8; Self::BLOCK_LEN];
        let aad_bit_len_octets = (alen as u64 * 8).to_le_bytes();
        let ciphertext_bit_len_octets = (clen as u64 * 8).to_le_bytes();
        bit_len_block[0.. 8].copy_from_slice(&aad_bit_len_octets);
        bit_len_block[8..16].copy_from_slice(&ciphertext_bit_len_octets);

        self.polyval.reset();

        self.polyval.polyval(aad);
        self.polyval.polyval(cleartext);
        self.polyval.polyval(&bit_len_block);

        for i in 0..Self::NONCE_LEN {
            self.polyval.h[i] ^= self.nonce[i];
        }
        self.polyval.h[15] &= 0x7f;

        // Expected TAG
        let mut tag = self.polyval.h.clone();
        self.cipher.encrypt(&mut tag);
        
        // Verify
        if bool::from(subtle::ConstantTimeEq::ct_eq(&tag1[..], &tag)) {
            // ok
        } else {
            panic!("TagMisMatch");
        }
    }
}
