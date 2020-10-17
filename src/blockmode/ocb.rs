// The OCB Authenticated-Encryption Algorithm
// https://tools.ietf.org/html/rfc7253
// 
// OCB: A Block-Cipher Mode of Operation for Efficient Authenticated Encryption
// https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/ocb/ocb-spec.pdf
use crate::aes::Aes128;
use super::dbl;

use subtle;

// 参考代码:
//      https://github.com/kmcallister/ocb.rs/blob/master/ocb_sys/ocb.c
//      https://web.cs.ucdavis.edu/~rogaway/ocb/news/code/ocb.c
// 


// 20           AEAD_AES_128_OCB_TAGLEN128  [RFC7253, Section 3.1]
// 21           AEAD_AES_128_OCB_TAGLEN96   [RFC7253, Section 3.1]
// 22           AEAD_AES_128_OCB_TAGLEN64   [RFC7253, Section 3.1]
// 23           AEAD_AES_192_OCB_TAGLEN128  [RFC7253, Section 3.1]
// 24           AEAD_AES_192_OCB_TAGLEN96   [RFC7253, Section 3.1]
// 25           AEAD_AES_192_OCB_TAGLEN64   [RFC7253, Section 3.1]
// 26           AEAD_AES_256_OCB_TAGLEN128  [RFC7253, Section 3.1]
// 27           AEAD_AES_256_OCB_TAGLEN96   [RFC7253, Section 3.1]
// 28           AEAD_AES_256_OCB_TAGLEN64   [RFC7253, Section 3.1]

// 6.  IANA Considerations
//    The Internet Assigned Numbers Authority (IANA) has defined a registry
//    for Authenticated Encryption with Associated Data parameters.  The
//    IANA has added the following entries to the AEAD Registry.  Each name
//    refers to a set of parameters defined in Section 3.1.
// 
//          +----------------------------+-------------+------------+
//          | Name                       |  Reference  | Numeric ID |
//          +----------------------------+-------------+------------+
//          | AEAD_AES_128_OCB_TAGLEN128 | Section 3.1 |     20     |
//          | AEAD_AES_128_OCB_TAGLEN96  | Section 3.1 |     21     |
//          | AEAD_AES_128_OCB_TAGLEN64  | Section 3.1 |     22     |
//          | AEAD_AES_192_OCB_TAGLEN128 | Section 3.1 |     23     |
//          | AEAD_AES_192_OCB_TAGLEN96  | Section 3.1 |     24     |
//          | AEAD_AES_192_OCB_TAGLEN64  | Section 3.1 |     25     |
//          | AEAD_AES_256_OCB_TAGLEN128 | Section 3.1 |     26     |
//          | AEAD_AES_256_OCB_TAGLEN96  | Section 3.1 |     27     |
//          | AEAD_AES_256_OCB_TAGLEN64  | Section 3.1 |     28     |
//          +----------------------------+-------------+------------+
// 

const MASK_1: u8 = 0b1000_0000;
const MASK_2: u8 = 0b0100_0000;
const MASK_3: u8 = 0b0010_0000;
const MASK_4: u8 = 0b0001_0000;
const MASK_5: u8 = 0b0000_1000;
const MASK_6: u8 = 0b0000_0100;
const MASK_7: u8 = 0b0000_0010;
const MASK_8: u8 = 0b0000_0001;


#[derive(Debug, Clone)]
pub struct Aes128OcbTag128 {
    cipher: Aes128,
    // nonce: [0u8; Self::BLOCK_LEN * 2],
    // nonce_len: usize,
    // bottom: usize,
    // stretch: [u8; Self::BLOCK_LEN + 8],
    offset_0: [u8; Self::BLOCK_LEN],
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

    const STRETCH_LEN: usize = Self::BLOCK_LEN + 8;

    pub fn new(key: &[u8], in_nonce: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        // assert_eq!(nonce.len(), Self::NONCE_LEN); // 96-Bits
        assert_eq!(Self::BLOCK_LEN, 16);
        assert!(in_nonce.len() >= Self::N_MIN && in_nonce.len() <= Self::N_MAX);

        let cipher = Aes128::new(key);

        // L_*
        let mut double_z1 = [0u8; Self::BLOCK_LEN];
        cipher.encrypt(&mut double_z1);

        // L_$
        let double_z2 = dbl(u128::from_be_bytes(double_z1));
        // L_0
        let double = dbl(double_z2).to_be_bytes();

        let nlen = in_nonce.len();
        let nlen_bits = nlen * 8;

        // Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N
        let mut nonce = [0u8; Self::BLOCK_LEN];
        nonce[16 - nlen..].copy_from_slice(&in_nonce);

        nonce[0] = ((Self::TAG_LEN as u8 * 8) % 128) << 1;
        nonce[16 - nlen - 1] |= 0x01;

        let bottom = (nonce[15] & 0b0011_1111) as usize;

        // Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6))
        let mut ktop = nonce.clone();
        ktop[15] &= 0b1100_0000;
        cipher.encrypt(&mut ktop);

        // Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
        // ktop || ktop[0..8] || ktop[1..9]
        let mut stretch = [0u8; Self::STRETCH_LEN];
        stretch[..Self::BLOCK_LEN].copy_from_slice(&ktop);
        let mut tmp = [0u8; 8];
        for i in 0..8 {
            tmp[i] = ktop[i] ^ ktop[i + 1];
        }
        stretch[Self::BLOCK_LEN..Self::STRETCH_LEN].copy_from_slice(&tmp);

        let mut stretch_bits = [false; Self::STRETCH_LEN * 8];
        for i in 0..Self::STRETCH_LEN {
            let byte = stretch[i];
            stretch_bits[i * 8 + 0] = byte & MASK_1 != 0;
            stretch_bits[i * 8 + 1] = byte & MASK_2 != 0;
            stretch_bits[i * 8 + 2] = byte & MASK_3 != 0;
            stretch_bits[i * 8 + 3] = byte & MASK_4 != 0;
            stretch_bits[i * 8 + 4] = byte & MASK_5 != 0;
            stretch_bits[i * 8 + 5] = byte & MASK_6 != 0;
            stretch_bits[i * 8 + 6] = byte & MASK_7 != 0;
            stretch_bits[i * 8 + 7] = byte & MASK_8 != 0;
        }

        // Offset_0 = Stretch[1+bottom..128+bottom]
        let mut offset_0 = [0u8; Self::BLOCK_LEN];
        let mut offset_0_bits = [false; Self::BLOCK_LEN * 8];
        let slice = &stretch_bits[bottom..Self::BLOCK_LEN * 8 + bottom];
        assert_eq!(slice.len(), Self::BLOCK_LEN * 8);
        offset_0_bits.copy_from_slice(slice);

        for (i, bits) in offset_0_bits.chunks(8).enumerate() {
            let mut byte = 0u8;
            for bit in bits.iter() {
                byte <<= 1;
                if *bit {
                    byte |= 1;
                }
            }
            offset_0[i] = byte;
        }

        Self {
            cipher,
            offset_0,
            double,
        }
    }

    // 4.1.  Processing Associated Data: HASH
    // https://tools.ietf.org/html/rfc7253#section-4.1
    fn hash(&mut self, aad: &[u8]) -> [u8; Self::BLOCK_LEN] {
        let alen = aad.len();

        // L_*
        let mut double_z1 = [0u8; Self::BLOCK_LEN];
        self.cipher.encrypt(&mut double_z1);
        // L_$
        let double_z2 = dbl(u128::from_be_bytes(double_z1));
        // L_0
        let double = dbl(double_z2).to_be_bytes();

        // Sum_0 = zeros(128)
        // Offset_0 = zeros(128)
        let mut sum = [0u8; Self::BLOCK_LEN];
        let mut offset = [0u8; Self::BLOCK_LEN];
        let mut block_idx = 1usize;
        for chunk in aad.chunks_exact(Self::BLOCK_LEN) {
            let mut double = self.double.clone();
            let ntz = block_idx.trailing_zeros();
            // if ntz > 0 {
            //     // TODO: 这个 double 序列的计算后面可以考虑使用缓存表。
            //     //       10万个 Blocks 当中，只需要 
            //     //       [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 64] 
            //     //       个 17 个 u128 的存储空间。
            //     for i in 1..ntz + 1 {
            //         double = dbl(u128::from_be_bytes(double.clone())).to_be_bytes();
            //     }
            // }
            if ntz > 0 {
                for _ in 0..ntz {
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

        block_idx -= 1;

        if alen % Self::BLOCK_LEN > 0 {
            // Process any whole blocks

            // Last Block
            let remainder = &aad[block_idx * Self::BLOCK_LEN..];

            // Offset_* = Offset_m xor L_*
            for i in 0..Self::BLOCK_LEN {
                offset[i] ^= double_z1[i];
            }

            // CipherInput = (A_* || 1 || zeros(127-bitlen(A_*))) xor Offset_*
            let mut block = [0u8; Self::BLOCK_LEN];
            block[..remainder.len()].copy_from_slice(remainder);
            block[remainder.len()] = 0x80;

            for i in 0..Self::BLOCK_LEN {
                block[i] ^= offset[i];
            }

            // Sum = Sum_m xor ENCIPHER(K, CipherInput)
            self.cipher.encrypt(&mut block);

            for i in 0..Self::BLOCK_LEN {
                sum[i] ^= block[i];
            }
        } else {
            // Process any final partial block; compute final hash value

        }

        sum
    }
    
    #[inline]
    pub fn ae_encrypt(&mut self, plaintext_and_ciphertext: &mut [u8]) {
        self.aead_encrypt(&[], plaintext_and_ciphertext);
    }
    
    #[inline]
    pub fn ae_decrypt(&mut self, ciphertext_and_plaintext: &mut [u8]) -> bool {
        self.aead_decrypt(&[], ciphertext_and_plaintext)
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
        let mut offset = self.offset_0.clone();

        // Checksum_0 = zeros(128)
        let mut checksum = [0u8; Self::BLOCK_LEN];

        // Process any whole blocks
        let mut block_idx = 1usize;
        for chunk in plaintext.chunks_exact_mut(Self::BLOCK_LEN) {
            // L_i = double(L_{i-1}) for every integer i > 0
            // 
            // Offset_0 = Stretch[1+bottom..128+bottom]
            // Checksum_0 = zeros(128)
            // Offset_i = Offset_{i-1} xor L_{ntz(i)}
            let mut double = self.double.clone(); // L_0
            let ntz = block_idx.trailing_zeros();
            // if ntz > 0 {
            //     // TODO: 这个 double 序列的计算后面可以考虑使用缓存表。
            //     //       10万个 Blocks 当中，只需要 
            //     //       [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 64] 
            //     //       个 17 个 u128 的存储空间。
            //     for i in 1..ntz + 1 {
            //         double = dbl(u128::from_be_bytes(double.clone())).to_be_bytes();
            //         println!("L_{}: {:?}", i, hex::encode(&double) );
            //     }
            // }
            if ntz > 0 {
                for _ in 0..ntz {
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

        block_idx -= 1;

        let mut double_z1 = [0u8; Self::BLOCK_LEN]; // L_*
        self.cipher.encrypt(&mut double_z1);
        let double_z2 = dbl(u128::from_be_bytes(double_z1)).to_be_bytes(); // L_$

        if plen % Self::BLOCK_LEN > 0 {
            // Process any final partial block and compute raw tag

            // Last Block
            let remainder = &mut plaintext[block_idx * Self::BLOCK_LEN..];

            // Offset_* = Offset_m xor L_*
            for i in 0..Self::BLOCK_LEN {
                offset[i] ^= double_z1[i];
            }

            // Pad = ENCIPHER(K, Offset_*)
            let mut pad = offset.clone();
            self.cipher.encrypt(&mut pad);

            for i in 0..remainder.len() {
                pad[i] ^= remainder[i];
            }

            for i in 0..remainder.len() {
                checksum[i] ^= remainder[i];
                remainder[i] = pad[i];
            }
            checksum[remainder.len()] ^= 0x80;
        }

        // Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A)
        // Tag = ENCIPHER(K, Checksum_m xor Offset_m xor L_$) xor HASH(K,A)
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
        let tag = &mut plaintext_and_ciphertext[plen..plen + Self::TAG_LEN];
        tag.copy_from_slice(&tag_block[..Self::TAG_LEN]);
    }

    pub fn aead_decrypt(&mut self, aad: &[u8], ciphertext_and_plaintext: &mut [u8]) -> bool {
        debug_assert!(aad.len() < Self::A_MAX);
        debug_assert!(ciphertext_and_plaintext.len() < Self::C_MAX);
        debug_assert!(ciphertext_and_plaintext.len() >= Self::TAG_LEN);

        let alen = aad.len();
        let clen = ciphertext_and_plaintext.len() - Self::TAG_LEN;

        let ciphertext = &mut ciphertext_and_plaintext[..clen];

        let mut double_z1 = [0u8; Self::BLOCK_LEN]; // L_*
        self.cipher.encrypt(&mut double_z1);
        let double_z2 = dbl(u128::from_be_bytes(double_z1)).to_be_bytes(); // L_$


        // Offset_0 = Stretch[1+bottom..128+bottom]
        let mut offset = self.offset_0.clone();

        // Checksum_0 = zeros(128)
        let mut checksum = [0u8; Self::BLOCK_LEN];

        // Process any whole blocks
        let mut block_idx = 1usize;
        for chunk in ciphertext.chunks_exact_mut(Self::BLOCK_LEN) {
            let mut double = self.double.clone(); // L_0

            // Offset_i = Offset_{i-1} xor L_{ntz(i)}
            let ntz = block_idx.trailing_zeros();
            if ntz > 0 {
                for _ in 0..ntz {
                    double = dbl(u128::from_be_bytes(double.clone())).to_be_bytes();
                }
            }
            for i in 0..Self::BLOCK_LEN {
                offset[i] ^= double[i];
            }

            // P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)
            for i in 0..Self::BLOCK_LEN {
                chunk[i] ^= offset[i];
            }
            self.cipher.decrypt(chunk);
            for i in 0..Self::BLOCK_LEN {
                chunk[i] ^= offset[i];
            }

            for i in 0..Self::BLOCK_LEN {
                checksum[i] ^= chunk[i];
            }

            block_idx += 1;
        }

        block_idx -= 1;

        if clen % Self::BLOCK_LEN > 0 {
            // Process any final partial block and compute raw tag

            // Last Block
            let remainder = &mut ciphertext[block_idx * Self::BLOCK_LEN..];

            // Offset_* = Offset_m xor L_*
            for i in 0..Self::BLOCK_LEN {
                offset[i] ^= double_z1[i];
            }

            // Pad = ENCIPHER(K, Offset_*)
            let mut pad = offset.clone();
            self.cipher.encrypt(&mut pad);

            // Checksum_* = Checksum_m xor (P_* || 1 || zeros(127-bitlen(P_*)))
            for i in 0..remainder.len() {
                remainder[i] ^= pad[i];
                checksum[i] ^= remainder[i];
                // remainder[i] = pad[i];
            }
            checksum[remainder.len()] ^= 0x80;
        }

        // Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A)
        // Tag = ENCIPHER(K, Checksum_m xor Offset_m xor L_$) xor HASH(K,A)
        let mut tag_block = [0u8; Self::BLOCK_LEN];
        for i in 0..Self::BLOCK_LEN {
            tag_block[i] = checksum[i] ^ offset[i] ^ double_z2[i];
        }
        self.cipher.encrypt(&mut tag_block);

        let aad_hash = self.hash(aad);
        for i in 0..Self::BLOCK_LEN {
            tag_block[i] ^= aad_hash[i];
        }
        
        // Verify

        // Input TAG
        let input_tag = &ciphertext_and_plaintext[clen..clen + Self::TAG_LEN];
        bool::from(subtle::ConstantTimeEq::ct_eq(input_tag, &tag_block[..]))
    }
}


#[test]
fn test_aes128_ocb_tag128_dec() {
    let key       = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let nonce     = hex::decode("BBAA9988776655443322110F").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F2021222324252627").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);

    let mut ciphertext_and_tag = hex::decode("4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15\
A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95\
A98CA5F3000B1479").unwrap();
    let ret = cipher.aead_decrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(ret, true);
    assert_eq!(&ciphertext_and_tag[..plen], &plaintext);
}

#[test]
fn test_aes128_ocb_tag128_enc() {
    // Appendix A.  Sample Results
    // https://tools.ietf.org/html/rfc7253#appendix-A
    let key       = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();


    let nonce     = hex::decode("BBAA99887766554433221100").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("785407BFFFC8AD9EDCC5520AC9111EE6").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221101").unwrap();
    let aad       = hex::decode("0001020304050607").unwrap();
    let plaintext = hex::decode("0001020304050607").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221102").unwrap();
    let aad       = hex::decode("0001020304050607").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("81017F8203F081277152FADE694A0A00").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221103").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("0001020304050607").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221104").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5\
701C1CCEC8FC3358").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221105").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("8CF761B6902EF764462AD86498CA6B97").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221106").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436B\
DF06D8FA1ECA343D").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221107").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("1CA2207308C87C010756104D8840CE1952F09673A448A122\
C92C62241051F57356D7F3C90BB0E07F").unwrap()[..]);
    
    let nonce     = hex::decode("BBAA99887766554433221108").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("6DC225A071FC1B9F7C69F93B0F1E10DE").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221109").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3C\
E725F32494B9F914D85C0B1EB38357FF").unwrap()[..]);


    let nonce     = hex::decode("BBAA9988776655443322110A").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("BD6F6C496201C69296C11EFD138A467ABD3C707924B964DE\
AFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240").unwrap()[..]);


    let nonce     = hex::decode("BBAA9988776655443322110B").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("FE80690BEE8A485D11F32965BC9D2A32").unwrap()[..]);
    

    let nonce     = hex::decode("BBAA9988776655443322110C").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF4\
6040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF").unwrap()[..]);


    let nonce     = hex::decode("BBAA9988776655443322110D").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F2021222324252627").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F2021222324252627").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("D5CA91748410C1751FF8A2F618255B68A0A12E093FF45460\
6E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483\
A7035490C5769E60").unwrap()[..]);


    let nonce     = hex::decode("BBAA9988776655443322110E").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F2021222324252627").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("C5CD9D1850C141E358649994EE701B68").unwrap()[..]);

    
    let nonce     = hex::decode("BBAA9988776655443322110F").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F2021222324252627").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let mut cipher = Aes128OcbTag128::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15\
A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95\
A98CA5F3000B1479").unwrap()[..]);
}