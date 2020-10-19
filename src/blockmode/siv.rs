// NIST Special Publication 800-38B
// Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication
// https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-38b.pdf
// 
// The AES-CMAC Algorithm
// https://tools.ietf.org/html/rfc4493
// 
// Synthetic Initialization Vector (SIV) Authenticated Encryption Using the Advanced Encryption Standard (AES)
// https://tools.ietf.org/html/rfc5297
// 
// Block Cipher Techniques
// https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-development
// 
use crate::aes::{Aes128, Aes192, Aes256};
use super::dbl;

use subtle;


macro_rules! impl_block_cipher_with_siv_cmac_mode {
    ($name:tt, $cipher:tt) => {

        #[derive(Debug, Clone)]
        pub struct $name {
            cipher: $cipher,
            cmac_cipher: $cipher,
            cmac_k1: [u8; Self::BLOCK_LEN],
            cmac_k2: [u8; Self::BLOCK_LEN],
        }

        impl $name {
            pub const KEY_LEN: usize   = $cipher::KEY_LEN * 2; // 16 Byte Cipher Key, 16 Byte CMac Key
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const TAG_LEN: usize   = 16;
            
            // NOTE: 实际上是 2 ^ 132，但是这超出了 u64 的最大值。
            pub const P_MAX: usize = usize::MAX - 16;
            pub const A_MAX: usize = usize::MAX; // NOTE: 实际上是 unlimited
            pub const C_MAX: usize = usize::MAX;

            pub const N_MIN: usize = 1;
            pub const N_MAX: usize = usize::MAX;

            const BLOCK_ZERO: [u8; Self::BLOCK_LEN] = [0u8; Self::BLOCK_LEN];
            // 1^64 || 0^1 || 1^31 || 0^1 || 1^31
            const V1: [u8; Self::BLOCK_LEN] = [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
                0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 
            ];

            pub fn new(key: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);

                // CMac Cipher Key
                let k1 = &key[..$cipher::KEY_LEN];
                // Cipher Key
                let k2 = &key[$cipher::KEY_LEN..];

                let cipher = $cipher::new(k2);
                let cmac_cipher = $cipher::new(k1);
                
                // 2.3.  Subkey Generation Algorithm
                // https://tools.ietf.org/html/rfc4493#section-2.3
                let mut cmac_k1 = [0u8; Self::BLOCK_LEN];
                cmac_cipher.encrypt(&mut cmac_k1);

                let cmac_k1 = dbl(u128::from_be_bytes(cmac_k1)).to_be_bytes();
                let cmac_k2 = dbl(u128::from_be_bytes(cmac_k1)).to_be_bytes();

                Self { cipher, cmac_cipher, cmac_k1, cmac_k2 }
            }

            #[inline]
            fn cmac(&self, m: &[u8]) -> [u8; Self::BLOCK_LEN] {
                // 2.4.  MAC Generation Algorithm
                // https://tools.ietf.org/html/rfc4493#section-2.4
                let len = m.len();
                
                let mut padding_block = [
                    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ];
                
                if len < Self::BLOCK_LEN {
                    padding_block[..m.len()].copy_from_slice(&m);
                    padding_block[m.len()] = 0x80;

                    for i in 0..Self::BLOCK_LEN {
                        padding_block[i] ^= self.cmac_k2[i];
                    }

                    self.cmac_cipher.encrypt(&mut padding_block);
                    return padding_block;
                }

                if len == Self::BLOCK_LEN {
                    let mut block = self.cmac_k1.clone();
                    for i in 0..Self::BLOCK_LEN {
                        block[i] ^= m[i];
                    }

                    self.cmac_cipher.encrypt(&mut block);
                    return block;
                }

                let n = len / Self::BLOCK_LEN;
                let r = len % Self::BLOCK_LEN;

                let mn = if r == 0 { n - 1 } else { n };
                let mut x = [0u8; Self::BLOCK_LEN];

                for i in 0..mn {
                    let start = i * Self::BLOCK_LEN;
                    let end   = start + Self::BLOCK_LEN;
                    let block = &m[start..end];
                    debug_assert_eq!(block.len(), Self::BLOCK_LEN);

                    for i2 in 0..Self::BLOCK_LEN {
                        x[i2] ^= block[i2];
                    }
                    
                    self.cmac_cipher.encrypt(&mut x);
                }

                let last_block_offset = mn * Self::BLOCK_LEN;
                let last_block = &m[last_block_offset..];
                let last_block_len = last_block.len();

                if last_block_len == Self::BLOCK_LEN {
                    let block = last_block;
                    for i in 0..Self::BLOCK_LEN {
                        x[i] ^= block[i] ^ self.cmac_k1[i];
                    }
                } else {
                    let mut block = padding_block;
                    block[..last_block_len].copy_from_slice(&last_block);
                    block[last_block_len] = 0x80;

                    for i in 0..Self::BLOCK_LEN {
                        x[i] ^= block[i] ^ self.cmac_k2[i];
                    }
                }

                self.cmac_cipher.encrypt(&mut x);

                return x;
            }

            #[inline]
            fn siv(&self, components: &[&[u8]], payload: &[u8]) -> [u8; Self::BLOCK_LEN] {
                // 2.4.  S2V
                // https://tools.ietf.org/html/rfc5297#section-2.4

                // a vector of associated data AD[ ] where the number 
                // of components in the vector is not greater than 126
                // https://tools.ietf.org/html/rfc5297#section-2.6
                assert!(components.len() < 126);

                if components.is_empty() && payload.is_empty() {
                    // indicates a string that is 127 zero bits concatenated with a
                    // single one bit, that is 0^127 || 1^1.
                    let one = 1u128.to_be_bytes();
                    return self.cmac(&one);
                }

                let mut d = self.cmac(&Self::BLOCK_ZERO);
                for aad in components.iter() {
                    let d1 = dbl(u128::from_be_bytes(d.clone())).to_be_bytes();
                    let d2 = self.cmac(aad);

                    for i in 0..Self::BLOCK_LEN {
                        d[i] = d1[i] ^ d2[i];
                    }
                }

                let plen = payload.len();
                if plen >= Self::BLOCK_LEN {
                    let n = plen - Self::BLOCK_LEN;
                    // FIXME: 消除 Alloc，这个需要 CMAC 算法分离 LastBlock 处理部分。
                    let mut data = payload.to_vec();
                    let block = &mut data[n..];

                    for i in 0..Self::BLOCK_LEN {
                        block[i] ^= d[i];
                    }

                    return self.cmac(&data);
                } else {
                    // T = dbl(D) xor pad(Sn)
                    let mut t = dbl(u128::from_be_bytes(d)).to_be_bytes();

                    for i in 0..plen {
                        t[i] ^= payload[i];
                    }
                    t[plen] ^= 0b1000_0000;

                    return self.cmac(&t);
                }
            }

            #[inline]
            fn ctr_incr(&self, counter_block: &mut [u8; Self::BLOCK_LEN]) {
                let n = u128::from_be_bytes(*counter_block).wrapping_add(1).to_be_bytes();
                counter_block.copy_from_slice(&n);
            }

            /// Deterministic Authenticated Encryption
            pub fn aead_encrypt(&self, components: &[&[u8]], plaintext_and_ciphertext: &mut [u8]) {
                // 2.6.  SIV Encrypt
                // https://tools.ietf.org/html/rfc5297#section-2.6
                debug_assert!(components.len() < 126);
                debug_assert!(plaintext_and_ciphertext.len() < Self::P_MAX + Self::TAG_LEN);
                debug_assert!(plaintext_and_ciphertext.len() >= Self::TAG_LEN);

                let plen = plaintext_and_ciphertext.len() - Self::TAG_LEN;
                let plaintext = &mut plaintext_and_ciphertext[Self::TAG_LEN..];

                // V = S2V(K1, AD1, ..., ADn, P)
                let v = self.siv(components, &plaintext);
                // Q = V bitand (1^64 || 0^1 || 1^31 || 0^1 || 1^31)
                let mut q = v.clone();
                for i in 0..Self::BLOCK_LEN {
                    q[i] &= Self::V1[i];
                }

                // CTR Counter
                let mut counter = u128::from_be_bytes(q);

                // m = (len(P) + 127)/128
                for chunk in plaintext.chunks_mut(Self::BLOCK_LEN) {
                    let mut keystream_block = counter.clone().to_be_bytes();

                    self.cipher.encrypt(&mut keystream_block);
                    for i in 0..chunk.len() {
                        chunk[i] ^= keystream_block[i];
                    }

                    counter = counter.wrapping_add(1);
                }

                let iv = &mut plaintext_and_ciphertext[..Self::TAG_LEN];
                iv.copy_from_slice(&v[..Self::TAG_LEN]);
            }

            pub fn aead_decrypt(&self, components: &[&[u8]], ciphertext_and_plaintext: &mut [u8]) -> bool {
                debug_assert!(components.len() < 126);
                debug_assert!(ciphertext_and_plaintext.len() <= Self::C_MAX);
                debug_assert!(ciphertext_and_plaintext.len() >= Self::TAG_LEN);

                // 2.7.  SIV Decrypt
                // https://tools.ietf.org/html/rfc5297#section-2.7
                let mut input_iv = [0u8; Self::BLOCK_LEN];
                input_iv.copy_from_slice(&ciphertext_and_plaintext[..Self::TAG_LEN]);

                let clen = ciphertext_and_plaintext.len() - Self::TAG_LEN;
                let ciphertext = &mut ciphertext_and_plaintext[Self::TAG_LEN..];

                let mut q = input_iv.clone();
                for i in 0..Self::BLOCK_LEN {
                    q[i] &= Self::V1[i];
                }

                // CTR Counter
                let mut counter = u128::from_be_bytes(q);

                for chunk in ciphertext.chunks_mut(Self::BLOCK_LEN) {
                    let mut output_block = counter.clone().to_be_bytes();
                    self.cipher.encrypt(&mut output_block);
                    for i in 0..chunk.len() {
                        chunk[i] ^= output_block[i];
                    }

                    counter = counter.wrapping_add(1);
                }

                // T = S2V(K1, AD1, ..., ADn, P)
                let plaintext = &ciphertext_and_plaintext[Self::TAG_LEN..];
                let tag = self.siv(components, &plaintext);

                // Verify
                bool::from(subtle::ConstantTimeEq::ct_eq(&tag[..], &input_iv[..]))
            }
        }
    }
}



// 15           AEAD_AES_SIV_CMAC_256       [RFC5297]
// 16           AEAD_AES_SIV_CMAC_384       [RFC5297]
// 17           AEAD_AES_SIV_CMAC_512       [RFC5297]

// AEAD_AES_SIV_CMAC_256
//     K_LEN  is 32 octets.
//     P_MAX  is 2^132 octets.
//     A_MAX  is unlimited.
//     N_MIN  is 1 octet.
//     N_MAX  is unlimited.
//     C_MAX  is 2^132 + 16 octets.

// AEAD_AES_SIV_CMAC_384
//     K_LEN  is 48 octets.
//     P_MAX  is 2^132 octets.
//     A_MAX  is unlimited.
//     N_MIN  is 1 octet.
//     N_MAX  is unlimited.
//     C_MAX  is 2^132 + 16 octets

// AEAD_AES_SIV_CMAC_512
//     K_LEN  is 64 octets.
//     P_MAX  is 2^132 octets.
//     A_MAX  is unlimited.
//     N_MIN  is 1 octet.
//     N_MAX  is unlimited.
//     C_MAX  is 2^132 + 16 octets.

// 6.1.  AEAD_AES_SIV_CMAC_256
// https://tools.ietf.org/html/rfc5297#section-6.1
impl_block_cipher_with_siv_cmac_mode!(AesSivCmac256, Aes128);
impl_block_cipher_with_siv_cmac_mode!(AesSivCmac384, Aes192);
impl_block_cipher_with_siv_cmac_mode!(AesSivCmac512, Aes256);


#[test]
fn test_aes_siv_cmac256_dec() {
    let key       = hex::decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0\
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
    let aad       = hex::decode("101112131415161718191a1b1c1d1e1f\
2021222324252627").unwrap();
    let plaintext = hex::decode("112233445566778899aabbccddee").unwrap();
    let mut ciphertext_and_tag = hex::decode("85632d07c6e8f37f950acd320a2ecc93\
40c02b9690c4dc04daef7f6afe5c").unwrap();

    let cipher = AesSivCmac256::new(&key);
    let ret = cipher.aead_decrypt(&[&aad], &mut ciphertext_and_tag);
    assert_eq!(ret, true);
    assert_eq!(&ciphertext_and_tag[AesSivCmac256::TAG_LEN..], &plaintext[..]);

}

#[test]
fn test_aes_siv_cmac256_enc() {
    // A.1.  Deterministic Authenticated Encryption Example
    // https://tools.ietf.org/html/rfc5297#appendix-A.1
    let key       = hex::decode("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0\
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
    let aad       = hex::decode("101112131415161718191a1b1c1d1e1f\
2021222324252627").unwrap();
    let plaintext = hex::decode("112233445566778899aabbccddee").unwrap();

    let plen      = plaintext.len();
    // NOTE: Layout = IV || C
    let mut ciphertext_and_tag = plaintext.clone();
    for _ in 0..AesSivCmac256::TAG_LEN {
        ciphertext_and_tag.insert(0, 0);
    }

    let cipher = AesSivCmac256::new(&key);
    cipher.aead_encrypt(&[&aad], &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..],
        &hex::decode("85632d07c6e8f37f950acd320a2ecc93\
40c02b9690c4dc04daef7f6afe5c").unwrap()[..]);

    
    // A.2.  Nonce-Based Authenticated Encryption Example
    // https://tools.ietf.org/html/rfc5297#appendix-A.2
    let key       = hex::decode("7f7e7d7c7b7a79787776757473727170\
404142434445464748494a4b4c4d4e4f").unwrap();
    let ad1       = hex::decode("\
00112233445566778899aabbccddeeff\
deaddadadeaddadaffeeddccbbaa9988\
7766554433221100").unwrap();
    let ad2       = hex::decode("102030405060708090a0").unwrap();
    let nonce     = hex::decode("09f911029d74e35bd84156c5635688c0").unwrap();
    let plaintext = hex::decode("7468697320697320736f6d6520706c61\
696e7465787420746f20656e63727970\
74207573696e67205349562d414553").unwrap();
    let plen      = plaintext.len();
    // NOTE: Layout = IV || C
    let mut ciphertext_and_tag = plaintext.clone();
    for _ in 0..AesSivCmac256::TAG_LEN {
        ciphertext_and_tag.insert(0, 0);
    }
    let cipher = AesSivCmac256::new(&key);
    cipher.aead_encrypt(&[&ad1, &ad2, &nonce], &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("7bdb6e3b432667eb06f4d14bff2fbd0f\
cb900f2fddbe404326601965c889bf17\
dba77ceb094fa663b7a3f748ba8af829\
ea64ad544a272e9c485b62a3fd5c0d").unwrap()[..]);
}




// TODO: 将来考虑将 Cmac 独立出来？
#[derive(Debug, Clone)]
struct Aes128Cmac {
    cipher: Aes128,
    k1: [u8; Self::BLOCK_LEN],
    k2: [u8; Self::BLOCK_LEN],
}

impl Aes128Cmac {
    pub const KEY_LEN: usize   = Aes128::KEY_LEN;
    pub const BLOCK_LEN: usize = Aes128::BLOCK_LEN;
    pub const TAG_LEN: usize   = 16;

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        let cipher = Aes128::new(key);

        let mut zeros = [0u8; Self::BLOCK_LEN];
        cipher.encrypt(&mut zeros);

        let k1 = dbl(u128::from_be_bytes(zeros)).to_be_bytes();
        let k2 = dbl(u128::from_be_bytes(k1)).to_be_bytes();

        Self { cipher, k1, k2, }
    }


    pub fn hash(&self, m: &[u8]) -> [u8; Self::BLOCK_LEN] {
        // 2.4.  MAC Generation Algorithm
        // https://tools.ietf.org/html/rfc4493#section-2.4
        let len = m.len();
        
        let mut padding_block = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        
        if len < Self::BLOCK_LEN {
            padding_block[..m.len()].copy_from_slice(&m);
            padding_block[m.len()] = 0x80;

            for i in 0..Self::BLOCK_LEN {
                padding_block[i] ^= self.k2[i];
            }

            self.cipher.encrypt(&mut padding_block);
            return padding_block;
        }

        if len == Self::BLOCK_LEN {
            let mut block = self.k1.clone();
            for i in 0..Self::BLOCK_LEN {
                block[i] ^= m[i];
            }

            self.cipher.encrypt(&mut block);
            return block;
        }

        let n = len / Self::BLOCK_LEN;
        let r = len % Self::BLOCK_LEN;

        let mn = if r == 0 { n - 1 } else { n };
        let mut x = [0u8; Self::BLOCK_LEN];

        for i in 0..mn {
            let start = i * Self::BLOCK_LEN;
            let end   = start + Self::BLOCK_LEN;
            let block = &m[start..end];
            debug_assert_eq!(block.len(), Self::BLOCK_LEN);

            for i2 in 0..Self::BLOCK_LEN {
                x[i2] ^= block[i2];
            }
            
            self.cipher.encrypt(&mut x);
        }

        let last_block_offset = mn * Self::BLOCK_LEN;
        let last_block = &m[last_block_offset..];
        let last_block_len = last_block.len();

        if last_block_len == Self::BLOCK_LEN {
            let block = last_block;
            for i in 0..Self::BLOCK_LEN {
                x[i] ^= block[i] ^ self.k1[i];
            }
        } else {
            let mut block = padding_block;
            block[..last_block_len].copy_from_slice(&last_block);
            block[last_block_len] = 0x80;

            for i in 0..Self::BLOCK_LEN {
                x[i] ^= block[i] ^ self.k2[i];
            }
        }

        self.cipher.encrypt(&mut x);

        return x;
    }
}

#[test]
fn test_aes128_cmac() {
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();

    let cmac = Aes128Cmac::new(&key);

    let k1 = cmac.k1;
    let k2 = cmac.k2;
    assert_eq!(&k1[..], &hex::decode("fbeed618357133667c85e08f7236a8de").unwrap()[..]);
    assert_eq!(&k2[..], &hex::decode("f7ddac306ae266ccf90bc11ee46d513b").unwrap()[..]);

    let m = hex::decode("").unwrap();
    let mac = cmac.hash(&m);
    assert_eq!(&mac[..], &hex::decode("bb1d6929e95937287fa37d129b756746").unwrap()[..] );

    let m = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let mac = cmac.hash(&m);
    assert_eq!(&mac[..], &hex::decode("070a16b46b4d4144f79bdd9dd04a287c").unwrap()[..] );

    let m = hex::decode("6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411").unwrap();
    let mac = cmac.hash(&m);
    assert_eq!(&mac[..], &hex::decode("dfa66747de9ae63030ca32611497c827").unwrap()[..] );

    let m = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710").unwrap();
    let mac = cmac.hash(&m);
    assert_eq!(&mac[..], &hex::decode("51f0bebf7e3b9d92fc49741779363cfe").unwrap()[..] );
}