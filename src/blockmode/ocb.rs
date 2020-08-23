// The OCB Authenticated-Encryption Algorithm
// https://tools.ietf.org/html/rfc7253
// 
// OCB: A Block-Cipher Mode of Operation for Efficient Authenticated Encryption
// https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/ocb/ocb-spec.pdf
use crate::aes::Aes128;

use subtle;

// 20           AEAD_AES_128_OCB_TAGLEN128  [RFC7253, Section 3.1]
// 21           AEAD_AES_128_OCB_TAGLEN96   [RFC7253, Section 3.1]
// 22           AEAD_AES_128_OCB_TAGLEN64   [RFC7253, Section 3.1]
// 23           AEAD_AES_192_OCB_TAGLEN128  [RFC7253, Section 3.1]
// 24           AEAD_AES_192_OCB_TAGLEN96   [RFC7253, Section 3.1]
// 25           AEAD_AES_192_OCB_TAGLEN64   [RFC7253, Section 3.1]
// 26           AEAD_AES_256_OCB_TAGLEN128  [RFC7253, Section 3.1]
// 27           AEAD_AES_256_OCB_TAGLEN96   [RFC7253, Section 3.1]
// 28           AEAD_AES_256_OCB_TAGLEN64   [RFC7253, Section 3.1]


// 2.  Notation and Basic Operations
// https://tools.ietf.org/html/rfc7253#section-2
// 
// double(S)     If S[1] == 0, then double(S) == (S[2..128] || 0);
//              otherwise, double(S) == (S[2..128] || 0) xor
//              (zeros(120) || 10000111).
#[inline]
fn dbl(s: u128) -> u128 {
    (s << 1) ^ ( (((s as i128) >> 127) as u128) & 0b10000111)
}


#[derive(Debug, Clone)]
pub struct Aes128OcbTag128 {
    cipher: Aes128,
    // nonce: [0u8; Self::BLOCK_LEN * 2],
    nonce_len: usize,
    stretch: [u8; Self::BLOCK_LEN + 8],
    double: [u8; Self::BLOCK_LEN],
}

impl Aes128OcbTag128 {
    pub const KEY_LEN: usize   = Aes128::KEY_LEN;
    pub const BLOCK_LEN: usize = Aes128::BLOCK_LEN;
    pub const TAG_LEN: usize   = 16;

    // pub const NONCE_LEN: usize = 12;
    pub const N_MIN: usize = 1;
    pub const N_MAX: usize = 15; // 120-bits

    pub const P_MAX: usize = 68719476736;                 // 2^36
    pub const A_MAX: usize = 68719476736;                 // 2^36
    pub const C_MAX: usize = 68719476736 + Self::TAG_LEN; // 2^36 + 16


    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        // assert_eq!(nonce.len(), Self::NONCE_LEN); // 96-Bits
        assert_eq!(Self::BLOCK_LEN, 16);
        assert!(nonce.len() >= Self::N_MIN && nonce.len() <= Self::N_MAX);

        let cipher = Aes128::new(key);

        let nlen = nonce.len();
        let nlen_bits = nlen * 8;

        // 步骤一
        let mut bits = [0u8; Self::BLOCK_LEN * 2];
        // 0 .. 7
        bits[0] = ((Self::TAG_LEN as u8 * 8) % 128) << 1;
        // 7 .. 7 + N_LEN_BITS (all zeros)

        // 7 + N_LEN_BITS .. 7 + N_LEN_BITS + 1
        bits[nlen] = 1;
        // 7 + N_LEN_BITS + 1 .. 7 + N_LEN_BITS + 1 + N_LEN_BITS
        let nonce_len = nlen + 1 + nlen;
        bits[nlen + 1..nonce_len].copy_from_slice(nonce);

        let nonce = &bits[..nonce_len];

        // 步骤二
        // 122 .. 128
        let bottom = nonce[15] & 0b0011_1111;
        // 0 .. 122 || 00_0000
        let mut ktop = [0u8; Self::BLOCK_LEN];
        ktop[0..15].copy_from_slice(&nonce[0..15]);
        ktop[16] = nonce[16] & 0b1100_0000;
        cipher.encrypt(&mut ktop);

        // 步骤三
        // Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
        // 0..63  ktop[0..8]
        // 8..72  ktop[0..8]
        // ktop || ktop[0..8] || ktop[1..9]
        let mut stretch = [0u8; Self::BLOCK_LEN + 8];
        stretch[..Self::BLOCK_LEN].copy_from_slice(&ktop);
        let mut tmp = [0u8; 8];
        for i in 0..8 {
            tmp[i] = ktop[i] ^ ktop[i + 1];
        }
        stretch[Self::BLOCK_LEN..Self::BLOCK_LEN + 8].copy_from_slice(&tmp);

        // L_*
        let mut double_z1 = [0u8; Self::BLOCK_LEN];
        cipher.encrypt(&mut double_z1);
        // L_$
        let double_z2 = dbl(u128::from_be_bytes(double_z1));
        // L_0
        let double = dbl(double_z2).to_be_bytes();

        Self {
            cipher,
            // nonce: bits,
            nonce_len,
            bottom: bottom as usize,
            stretch,
            double,
        }
    }

    // 4.1.  Processing Associated Data: HASH
    // https://tools.ietf.org/html/rfc7253#section-4.1
    fn hash(&mut self, aad: &[u8]) -> [u8; Self::BLOCK_LEN] {
        let alen = aad.len();

        // L_*
        let mut double_z1 = [0u8; Self::BLOCK_LEN];
        cipher.encrypt(&mut double_z1);
        // L_$
        let double_z2 = dbl(u128::from_be_bytes(double_z1.clone()));
        // L_0
        let double = dbl(double_z2).to_be_bytes();

        let mut sum = [0u8; Self::BLOCK_LEN];
        let mut offset = [0u8; Self::BLOCK_LEN];
        let mut block_idx = 0usize;
        for chunk in aad.chunks_exact(Self::BLOCK_LEN) {
            let mut double = self.double.clone();
            let ntz = block_idx.trailing_zeros();
            if ntz > 0 {
                // TODO: 这个 double 序列的计算后面可以考虑使用缓存表。
                //       10万个 Blocks 当中，只需要 
                //       [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 64] 
                //       个 17 个 u128 的存储空间。
                for i in 1..ntz + 1 {
                    double = dbl(u128::from_be_bytes(double.clone())).to_be_bytes();
                }
            }

            // Offset_i = Offset_{i-1} xor L_{ntz(i)}
            for i in 0..Self::BLOCK_LEN {
                offset[i] ^= double[i];
            }
            
            // Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)
            let mut block = offset.clone();
            for i in 0..Self::BLOCK_LEN {
                block[i] = chunk[i] ^ offset[i];
            }
            self.cipher.encrypt(&mut block);

            for i in 0..Self::BLOCK_LEN {
                sum[i] ^= block[i];
            }

            block_idx += 1;
        }

        if (block_idx + 1) * Self::BLOCK_LEN < alen {
            // Last Block
            let remainder = &aad[(block_idx + 1) * Self::BLOCK_LEN..];

            // Offset_* = Offset_m xor L_*
            for i in 0..Self::BLOCK_LEN {
                offset[i] ^= double_z1[i];
            }

            // CipherInput = (A_* || 1 || zeros(127-bitlen(A_*))) xor Offset_*
            let mut block = [0u8; Self::BLOCK_LEN];
            block[..remainder.len()].copy_from_slice(remainder);
            block[remainder.len() + 1] = 0x80;
            for i in 0..remainder.len() {
                block[i] ^= offset[i];
            }
            // Sum = Sum_m xor ENCIPHER(K, CipherInput)
            self.cipher.encrypt(&mut block);
            for i in 0..remainder.len() {
                sum[i] ^= block[i];
            }
        }

        sum
    }

    pub fn aead_encrypt(&mut self, aad: &[u8], plaintext_and_ciphertext: &mut [u8]) {
        debug_assert!(aad.len() < Self::A_MAX);
        debug_assert!(plaintext_and_ciphertext.len() < Self::C_MAX);
        debug_assert!(plaintext_and_ciphertext.len() >= Self::TAG_LEN);

        let alen = aad.len();
        let plen = plaintext_and_ciphertext.len() - Self::TAG_LEN;

        let plaintext = &plaintext_and_ciphertext[..plen];

        // Nonce-dependent and per-encryption variables
        let plaintext = &mut plaintext_and_ciphertext[..plen];

        // Offset_0 = Stretch[1+bottom..128+bottom]
        // FIXME: 考虑是否使用 bitvec 库。
        let bit_pos_start =   1 + self.bottom;
        let bit_pos_end   = 128 + self.bottom;
        let mut offset = self.stretch[..16];   // FIXME: 这里目前是伪代码！

        // Checksum_0 = zeros(128)
        let mut checksum = [0u8; Self::BLOCK_LEN];

        let mut block_idx = 0usize;
        for chunk in plaintext.chunks_exact_mut(Self::BLOCK_LEN) {
            // L_i = double(L_{i-1}) for every integer i > 0
            // 
            // Offset_0 = Stretch[1+bottom..128+bottom]
            // Checksum_0 = zeros(128)
            // Offset_i = Offset_{i-1} xor L_{ntz(i)}
            let mut double = self.double.clone();
            let ntz = block_idx.trailing_zeros();
            if ntz > 0 {
                // TODO: 这个 double 序列的计算后面可以考虑使用缓存表。
                //       10万个 Blocks 当中，只需要 
                //       [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 64] 
                //       个 17 个 u128 的存储空间。
                for i in 1..ntz + 1 {
                    double = dbl(u128::from_be_bytes(double.clone())).to_be_bytes();
                }
            }
            for i in 0..Self::BLOCK_LEN {
                offset[i] ^= double[i];
            }
            
            // C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)
            let mut block = offset.clone();
            for i in 0..Self::BLOCK_LEN {
                block[i] = chunk[i] ^ offset[i];
            }
            self.cipher.encrypt(&mut block);

            for i in 0..Self::BLOCK_LEN {
                checksum[i] ^= chunk[i];
                chunk[i] = block[i] ^ offset[i];
            }

            block_idx += 1;
        }

        let mut double_z1 = [0u8; Self::BLOCK_LEN]; // L_*
        cipher.encrypt(&mut double_z1);

        if (block_idx + 1) * Self::BLOCK_LEN < plen {
            // Last Block
            let remainder = &mut plaintext[(block_idx + 1) * Self::BLOCK_LEN..];

            // Pad = ENCIPHER(K, Offset_*)
            let mut block = offset.clone();
            for i in 0..Self::BLOCK_LEN {
                block[i] = double_z1[i] ^ offset[i];
            }
            self.cipher.encrypt(&mut block);

            for i in 0..remainder.len() {
                checksum[i] ^= remainder[i];
                remainder[i] ^= block[i];
            }

            checksum[remainder.len()] ^= 0x80;
            for i in (remainder.len() + 1)..Self::BLOCK_LEN {
                checksum[i] ^= 0x00;
            }
        }

        let double_z2 = dbl(u128::from_be_bytes(double_z1)).to_be_bytes(); // L_$

        // Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A)
        let mut tag_block = [0u8; Self::BLOCK_LEN];
        for i in 0..Self::BLOCK_LEN {
            tag_block[i] = checksum[i] ^ offset[i] ^ double_z2[i];
        }
        self.cipher.encrypt(&mut tag_block);

        let aad_hash = self.hash(aad);
        for i in 0..Self::BLOCK_LEN {
            tag_block[i] ^= aad_hash[i];
        }
        
        // save TAG
        let mut tag = &mut plaintext_and_ciphertext[plen..plen + Self::TAG_LEN];
        tag.copy_from_slice(&tag_block[..Self::TAG_LEN]);
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
    }
}