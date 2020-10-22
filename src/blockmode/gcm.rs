// Recommendation for Block Cipher Modes of Operation:  Galois/Counter Mode (GCM) and GMAC
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// 
// Galois/Counter Mode:
// https://en.wikipedia.org/wiki/Galois/Counter_Mode
use crate::util::xor_si128_inplace;
use crate::mac::GHash;
use crate::blockcipher::{
    Sm4,
    Aes128, Aes256, 
    Camellia128, Camellia256,
    Aria128, Aria256,
};

use subtle;



// NOTE: 
//      1. GCM 认证算法本身支持变长的 IV，但是目前普遍的实现都是限制 IV 长度至 12 Bytes。
//      2. GCM 只可以和 块大小为 16 Bytes 的块密码算法协同工作。
//      3. GCM 不接受用户输入的 BlockCounter。
// 

const GCM_BLOCK_LEN: usize = 16;


macro_rules! impl_block_cipher_with_gcm_mode {
    ($name:tt, $cipher:tt, $tlen:tt) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            cipher: $cipher,
            ghash: GHash,
            counter_block: [u8; Self::BLOCK_LEN],
            base_ectr: [u8; Self::BLOCK_LEN],
        }

        // 6.  AES GCM Algorithms for Secure Shell
        // https://tools.ietf.org/html/rfc5647#section-6
        impl $name {
            pub const KEY_LEN: usize   = $cipher::KEY_LEN;
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const TAG_LEN: usize   = $tlen;
            // NOTE: GCM 认证算法本身支持变长的 IV，但是目前普遍的实现都是限制 IV 长度至 12 Bytes。
            //       这样和 BlockCounter (u32) 合在一起 组成一个 Nonce，为 12 + 4 = 16 Bytes。
            pub const NONCE_LEN: usize = 12;
            
            pub const A_MAX: usize = 2305843009213693951; // 2 ** 61
            pub const P_MAX: usize = 68719476735;         // 2^36 - 31
            pub const C_MAX: usize = 68719476721;         // 2^36 - 15
            pub const N_MIN: usize = Self::NONCE_LEN;
            pub const N_MAX: usize = Self::NONCE_LEN;

            pub fn new(key: &[u8], iv: &[u8]) -> Self {
                // NOTE: GCM 只可以和 块大小为 16 Bytes 的块密码算法协同工作。
                assert_eq!(Self::BLOCK_LEN, GCM_BLOCK_LEN);
                assert_eq!(Self::BLOCK_LEN, GHash::BLOCK_LEN);
                assert_eq!(key.len(), Self::KEY_LEN);
                // NOTE: 前面 12 Bytes 为 IV，后面 4 Bytes 为 BlockCounter。
                //       BlockCounter 不接受用户的输入，如果输入了直接忽略。
                assert_eq!(iv.len(), Self::NONCE_LEN);

                let mut counter_block = [0u8; Self::BLOCK_LEN];
                counter_block[..Self::NONCE_LEN].copy_from_slice(&iv[..Self::NONCE_LEN]);
                counter_block[15] = 1; // 初始化计数器

                let cipher = $cipher::new(key);

                let mut base_ectr = counter_block.clone();
                cipher.encrypt(&mut base_ectr);

                // NOTE: 计算 Ghash 初始状态。
                let mut h = [0u8; Self::BLOCK_LEN];
                cipher.encrypt(&mut h);

                let ghash = GHash::new(&h);

                Self { cipher, ghash, counter_block, base_ectr }
            }

            #[inline]
            pub fn ae_encrypt(&mut self, plaintext_and_ciphertext: &mut [u8]) {
                self.aead_encrypt(&[], plaintext_and_ciphertext);
            }
            
            #[inline]
            pub fn ae_decrypt(&mut self, ciphertext_and_plaintext: &mut [u8]) -> bool {
                self.aead_decrypt(&[], ciphertext_and_plaintext)
            }
            
            #[inline]
            fn block_num_inc(nonce: &mut [u8; Self::BLOCK_LEN]) {
                // Counter inc
                for i in 1..5 {
                    nonce[16 - i] = nonce[16 - i].wrapping_add(1);
                    if nonce[16 - i] != 0 {
                        break;
                    }
                }
            }
            
            pub fn aead_encrypt(&mut self, aad: &[u8], plaintext_and_ciphertext: &mut [u8]) {
                debug_assert!(aad.len() < Self::A_MAX);
                debug_assert!(plaintext_and_ciphertext.len() < Self::P_MAX + Self::TAG_LEN);
                debug_assert!(plaintext_and_ciphertext.len() >= Self::TAG_LEN);

                let alen = aad.len();
                let plen = plaintext_and_ciphertext.len() - Self::TAG_LEN;
                let plaintext = &mut plaintext_and_ciphertext[..plen];

                let mut mac = self.ghash.clone();
                let mut counter_block = self.counter_block.clone();
                
                mac.update(aad);

                //////// Update ////////
                let n = plen / Self::BLOCK_LEN;
                for i in 0..n {
                    Self::block_num_inc(&mut counter_block);
                    
                    let mut ectr = counter_block.clone();
                    self.cipher.encrypt(&mut ectr);

                    let block = &mut plaintext[i * Self::BLOCK_LEN..i * Self::BLOCK_LEN + Self::BLOCK_LEN];
                    
                    xor_si128_inplace(block, &ectr);

                    mac.update(&block);
                }

                if plen % Self::BLOCK_LEN != 0 {
                    Self::block_num_inc(&mut counter_block);
                    
                    let mut ectr = counter_block.clone();
                    self.cipher.encrypt(&mut ectr);

                    let rem = &mut plaintext[n * Self::BLOCK_LEN..];
                    for i in 0..rem.len() {
                        rem[i] ^= ectr[i];
                    }

                    mac.update(&rem);
                }

                // Finalize
                let plen_bits: u64 = (plen as u64) * 8;
                let alen_bits: u64 = (alen as u64) * 8;
                
                let mut octets = [0u8; 16];
                let mut tag = [0u8; Self::TAG_LEN];
                tag[..Self::TAG_LEN].copy_from_slice(&self.base_ectr[..Self::TAG_LEN]);

                octets[0.. 8].copy_from_slice(&alen_bits.to_be_bytes());
                octets[8..16].copy_from_slice(&plen_bits.to_be_bytes());

                mac.update(&octets);

                let buf = mac.finalize();
                if Self::TAG_LEN == 16 {
                    xor_si128_inplace(&mut tag, &buf);
                } else {
                    for i in 0..Self::TAG_LEN {
                        tag[i] ^= buf[i];
                    }
                }

                let tag_out = &mut plaintext_and_ciphertext[plen..plen + Self::TAG_LEN];
                // Append Tag.
                tag_out.copy_from_slice(&tag);
            }

            pub fn aead_decrypt(&mut self, aad: &[u8], ciphertext_and_plaintext: &mut [u8]) -> bool {
                debug_assert!(aad.len() < Self::A_MAX);
                debug_assert!(ciphertext_and_plaintext.len() < Self::C_MAX + Self::TAG_LEN);
                debug_assert!(ciphertext_and_plaintext.len() >= Self::TAG_LEN);

                let alen = aad.len();
                let clen = ciphertext_and_plaintext.len() - Self::TAG_LEN;
                let ciphertext = &mut ciphertext_and_plaintext[..clen];

                let mut mac = self.ghash.clone();
                let mut counter_block = self.counter_block.clone();

                mac.update(&aad);

                //////////// Update ///////////////
                let n = clen / Self::BLOCK_LEN;
                for i in 0..n {
                    Self::block_num_inc(&mut counter_block);
                    
                    let mut ectr = counter_block.clone();
                    self.cipher.encrypt(&mut ectr);

                    let block = &mut ciphertext[i * Self::BLOCK_LEN..i * Self::BLOCK_LEN + Self::BLOCK_LEN];
                    
                    mac.update(&block);

                    xor_si128_inplace(block, &ectr);
                }

                if clen % Self::BLOCK_LEN != 0 {
                    Self::block_num_inc(&mut counter_block);
                    
                    let mut ectr = counter_block.clone();
                    self.cipher.encrypt(&mut ectr);

                    let rem = &mut ciphertext[n * Self::BLOCK_LEN..];

                    mac.update(&rem);

                    for i in 0..rem.len() {
                        rem[i] ^= ectr[i];
                    }
                }

                // Finalize
                let clen_bits: u64 = (clen as u64) * 8;
                let alen_bits: u64 = (alen as u64) * 8;
                
                let mut octets = [0u8; 16];
                let mut tag = [0u8; Self::TAG_LEN];
                tag[..Self::TAG_LEN].copy_from_slice(&self.base_ectr[..Self::TAG_LEN]);

                octets[0.. 8].copy_from_slice(&clen_bits.to_le_bytes());
                octets[8..16].copy_from_slice(&alen_bits.to_le_bytes());

                mac.update(&octets);
                let buf = mac.finalize();

                if Self::TAG_LEN == 16 {
                    xor_si128_inplace(&mut tag, &buf);
                } else {
                    for i in 0..Self::TAG_LEN {
                        tag[i] ^= buf[i];
                    }
                }

                // Verify
                let input_tag = &ciphertext_and_plaintext[clen..clen + Self::TAG_LEN];
                bool::from(subtle::ConstantTimeEq::ct_eq(input_tag, &tag[..]))
            }
        }
    }
}


// 1            AEAD_AES_128_GCM            [RFC5116]
// 5            AEAD_AES_128_GCM_8          [RFC5282]
// 7            AEAD_AES_128_GCM_12         [RFC5282]
// 
// 2            AEAD_AES_256_GCM            [RFC5116]
// 6            AEAD_AES_256_GCM_8          [RFC5282]
// 8            AEAD_AES_256_GCM_12         [RFC5282]

// AEAD_AES_256_GCM
//     This algorithm is identical to AEAD_AES_128_GCM, but with the
//     following differences:
// 
//         K_LEN is 32 octets, instead of 16 octets, and
//         AES-256 GCM is used instead of AES-128 GCM.

// AEAD_AES_256_GCM_8
//    This algorithm is identical to AEAD_AES_256_GCM (see Section 5.2 of
//    [RFC5116]), except that the tag length, t, is 8, and an
//    authentication tag with a length of 8 octets (64 bits) is used.
// 
//    An AEAD_AES_256_GCM_8 ciphertext is exactly 8 octets longer than its
//    corresponding plaintext.

// AEAD_AES_256_GCM_12
//    This algorithm is identical to AEAD_AES_256_GCM (see Section 5.2 of
//    [RFC5116], except that the tag length, t, is 12 and an authentication
//    tag with a length of 12 octets (64 bits) is used.
// 
//    An AEAD_AES_256_GCM_12 ciphertext is exactly 12 octets longer than
//    its corresponding plaintext.


// AEAD_AES_128_GCM
//       K_LEN is 16 octets,
//       P_MAX is 2^36 - 31 octets,
//       A_MAX is 2^61 - 1 octets,
//       N_MIN and N_MAX are both 12 octets, and
//       C_MAX is 2^36 - 15 octets.

// AEAD_AES_128_GCM_8
//     This algorithm is identical to AEAD_AES_128_GCM (see Section 5.1 of
//     [RFC5116]), except that the tag length, t, is 8, and an
//     authentication tag with a length of 8 octets (64 bits) is used.
// 
//     An AEAD_AES_128_GCM_8 ciphertext is exactly 8 octets longer than its
//     corresponding plaintext.

// AEAD_AES_128_GCM_12
//    This algorithm is identical to AEAD_AES_128_GCM (see Section 5.1 of
//    [RFC5116]), except that the tag length, t, is 12, and an
//    authentication tag with a length of 12 octets (64 bits) is used.
// 
//    An AEAD_AES_128_GCM_12 ciphertext is exactly 12 octets longer than
//    its corresponding plaintext.

impl_block_cipher_with_gcm_mode!(Aes128Gcm,   Aes128, 16); // TAG-LEN=16
impl_block_cipher_with_gcm_mode!(Aes128Gcm8,  Aes128,  8); // TAG-LEN= 8
impl_block_cipher_with_gcm_mode!(Aes128Gcm12, Aes128, 12); // TAG-LEN=12

impl_block_cipher_with_gcm_mode!(Aes256Gcm,   Aes256, 16); // TAG-LEN=16
impl_block_cipher_with_gcm_mode!(Aes256Gcm8,  Aes256,  8); // TAG-LEN= 8
impl_block_cipher_with_gcm_mode!(Aes256Gcm12, Aes256, 12); // TAG-LEN=12


impl_block_cipher_with_gcm_mode!(Sm4Gcm,         Sm4, 16);         // TAG-LEN=16
impl_block_cipher_with_gcm_mode!(Camellia128Gcm, Camellia128, 16); // TAG-LEN=16
impl_block_cipher_with_gcm_mode!(Aria128Gcm,     Aria128, 16);     // TAG-LEN=16

impl_block_cipher_with_gcm_mode!(Camellia256Gcm, Camellia256, 16); // TAG-LEN=16
impl_block_cipher_with_gcm_mode!(Aria256Gcm,     Aria256, 16);     // TAG-LEN=16


#[test]
fn test_aes128_gcm() {
    // B   AES Test Vectors, (Page-29)
    // https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

    // Test  Case  1
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let iv = hex::decode("000000000000000000000000").unwrap();
    let aad = [0u8; 0];
    let plaintext = [0u8; 0];
    let mut ciphertext_and_tag = [0u8; 0 + Aes128Gcm::TAG_LEN];

    let mut cipher = Aes128Gcm::new(&key, &iv);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("58e2fccefa7e3061367f1d57a4e7455a").unwrap()[..]);


    // Test  Case  2
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let iv = hex::decode("000000000000000000000000").unwrap();
    let aad = [0u8; 0];
    let plaintext = hex::decode("00000000000000000000000000000000").unwrap();
    let plen = plaintext.len();
    let alen = aad.len();
    let mut plaintext_and_ciphertext = plaintext.clone();
    plaintext_and_ciphertext.resize(plen + Aes128Gcm::TAG_LEN, 0);

    let mut cipher = Aes128Gcm::new(&key, &iv);
    cipher.aead_encrypt(&aad, &mut plaintext_and_ciphertext);

    assert_eq!(&plaintext_and_ciphertext[..plen], &hex::decode("0388dace60b6a392f328c2b971b2fe78").unwrap()[..]);
    assert_eq!(&plaintext_and_ciphertext[plen..], &hex::decode("ab6e47d42cec13bdf53a67b21257bddf").unwrap()[..]);


    // Test  Case  3
    let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
    let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];
    let plaintext = hex::decode("d9313225f88406e5a55909c5aff5269a\
86a7a9531534f7da2e4c303d8a318a72\
1c3c0c95956809532fcf0e2449a6b525\
b16aedf5aa0de657ba637b391aafd255").unwrap();
    let plen = plaintext.len();
    let alen = aad.len();
    let mut plaintext_and_ciphertext = plaintext.clone();
    plaintext_and_ciphertext.resize(plen + Aes128Gcm::TAG_LEN, 0);

    let mut cipher = Aes128Gcm::new(&key, &iv);
    cipher.aead_encrypt(&aad, &mut plaintext_and_ciphertext);
    assert_eq!(&plaintext_and_ciphertext[..plen], &hex::decode("42831ec2217774244b7221b784d0d49c\
e3aa212f2c02a4e035c17e2329aca12e\
21d514b25466931c7d8f6a5aac84aa05\
1ba30b396a0aac973d58e091473f5985").unwrap()[..]);
    assert_eq!(&plaintext_and_ciphertext[plen..], &hex::decode("4d5c2af327cd64a62cf35abd2ba6fab4").unwrap()[..]);


    // Test  Case  4
    let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
    let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeef\
abaddad2").unwrap();
    let plaintext = hex::decode("d9313225f88406e5a55909c5aff5269a\
86a7a9531534f7da2e4c303d8a318a72\
1c3c0c95956809532fcf0e2449a6b525\
b16aedf5aa0de657ba637b39").unwrap();
    let plen = plaintext.len();
    let alen = aad.len();
    let mut plaintext_and_ciphertext = plaintext.clone();
    plaintext_and_ciphertext.resize(plen + Aes128Gcm::TAG_LEN, 0);

    let mut cipher = Aes128Gcm::new(&key, &iv);
    cipher.aead_encrypt(&aad, &mut plaintext_and_ciphertext);
    assert_eq!(&plaintext_and_ciphertext[..plen], &hex::decode("42831ec2217774244b7221b784d0d49c\
e3aa212f2c02a4e035c17e2329aca12e\
21d514b25466931c7d8f6a5aac84aa05\
1ba30b396a0aac973d58e091").unwrap()[..]);
    assert_eq!(&plaintext_and_ciphertext[plen..], &hex::decode("5bc94fbc3221a5db94fae95ae7121a47").unwrap()[..]);
}