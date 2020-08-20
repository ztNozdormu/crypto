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
// AES-GCM-SIV: Specification and Analysis
// https://eprint.iacr.org/2017/168.pdf
// 
// AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption
// https://tools.ietf.org/html/rfc8452
// 
// Block Cipher Techniques
// https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-development
// 
use crate::aes::Aes128;

use subtle;


// 15           AEAD_AES_SIV_CMAC_256       [RFC5297]
// K_LEN=32
// 
// 16           AEAD_AES_SIV_CMAC_384       [RFC5297]
// 17           AEAD_AES_SIV_CMAC_512       [RFC5297]
// 
// 30           AEAD_AES_128_GCM_SIV        [RFC8452]
// 31           AEAD_AES_256_GCM_SIV        [RFC8452]


#[allow(dead_code)]
#[inline]
fn dbl2(s: u128) -> u128 {
    if s & 0x80000000000000000000000000000000 != 0 {
        (s << 1) ^ 0b10000111
    } else {
        s << 1
    }
}

// doubling operation
// https://github.com/briansmith/ring/issues/517
#[inline]
fn dbl(s: u128) -> u128 {
    (s << 1) ^ ( (((s as i128) >> 127) as u128) & 0b10000111)
}

struct MBuf<'a, 'b> {
    m1: &'a [u8],
    m2: &'b [u8],
    len: usize,
}

impl<'a, 'b> MBuf<'a, 'b> {
    pub fn new(m1: &'a [u8], m2: &'b [u8]) -> Self {
        let len = self.m1.len() + self.m2.len();
        Self { m1, m2, len, }
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl<'a, 'b> std::ops::Index<usize> for MBuf<'a, 'b> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        if index < m1.len() {
            &self.m1[index]
        } else {
            let i = index - m1.len();
            &self.m2[i]
        }
    }
}

impl<'a, 'b> std::ops::IndexMut<usize> for MBuf<'a, 'b> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        if index < m1.len() {
            &mut self.m1[index]
        } else {
            let i = index - m1.len();
            &mut self.m2[i]
        }
    }
}


// 6.1.  AEAD_AES_SIV_CMAC_256
// https://tools.ietf.org/html/rfc5297#section-6.1
#[derive(Debug, Clone)]
pub struct AesSivCmac256 {
    cipher: Aes128,
    cmac_cipher: Aes128,
    cmac_k1: [u8; Self::BLOCK_LEN],
    cmac_k2: [u8; Self::BLOCK_LEN],
    nonce: [0u8; Self::NONCE_LEN],
}

impl AesSivCmac256 {
    // K_LEN  is 32 octets.         // 16 Byte Cipher Key, 16 Byte CMac Key
    // P_MAX  is 2^132 octets.
    // A_MAX  is unlimited.
    // N_MIN  is 1 octet.
    // N_MAX  is unlimited.
    // C_MAX  is 2^132 + 16 octets.
    pub const KEY_LEN: usize   = Aes128::KEY_LEN * 2; // 16 Byte Cipher Key, 16 Byte CMac Key
    pub const BLOCK_LEN: usize = Aes128::BLOCK_LEN;
    pub const TAG_LEN: usize   = Aes128::BLOCK_LEN;
    
    pub const N_MIN: usize = 1;
    pub const N_MIN: usize = usize::MAX;
    // NOTE: Nonce 的长度暂时限定在 16 Bytes.
    pub const NONCE_LEN: usize = 16;

    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        assert_eq!(nonce.len(), Self::NONCE_LEN); // 96-Bits

        // CMac Cipher Key
        let k1 = &key[..Aes128::KEY_LEN];
        // Cipher Key
        let k2 = &key[Aes128::KEY_LEN..];

        let cipher = Aes128::new(k2);
        let cmac_cipher = Aes128::new(k1);
        
        // 2.3.  Subkey Generation Algorithm
        // https://tools.ietf.org/html/rfc4493#section-2.3
        // 
        // +   Step 1.  L := AES-128(K, const_Zero);                           +
        // +   Step 2.  if MSB(L) is equal to 0                                +
        // +            then    K1 := L << 1;                                  +
        // +            else    K1 := (L << 1) XOR const_Rb;                   +
        // +   Step 3.  if MSB(K1) is equal to 0                               +
        // +            then    K2 := K1 << 1;                                 +
        // +            else    K2 := (K1 << 1) XOR const_Rb;                  +
        // +   Step 4.  return K1, K2;                                         +
        // 
        const ZERO: [u8; Self::BLOCK_LEN] = [0u8; Self::BLOCK_LEN];
        let l = cmac_cipher.encrypt(&ZERO);
        let cmac_k1 = dbl(l).to_be_bytes();
        let cmac_k2 = dbl(cmac_k1).to_be_bytes();

        Self { cipher, cmac_cipher, cmac_k1, cmac_k2 }
    }

    #[inline]
    fn cmac(&self, m: &[u8]) -> [u8; Self::BLOCK_LEN] {
        // 2.4.  MAC Generation Algorithm
        // https://tools.ietf.org/html/rfc4493#section-2.4
        let len = m.len();
        // for number of blocks to be processed
        let n = len / Self::BLOCK_LEN;
        // for number of octets of last block
        let r = len % Self::BLOCK_LEN;
        // is the last block xor-ed with K1 or K2

        let mut x = [0u8; Self::BLOCK_LEN];

        if len == 0 {
            let mut m_last: [u8; Self::BLOCK_LEN] = [
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            // M_last := padding(M_n) XOR K2;
            for i in 0..Self::BLOCK_LEN {
                m_last[i] ^= self.cmac_k2[i];
                m_last[i] ^= x[i];
            }
            return self.cmac_cipher.encrypt(&m_last);
        }

        if len < Self::BLOCK_LEN {
            let mut m_last: [u8; Self::BLOCK_LEN] = [
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            // M_last := padding(M_n) XOR K2;
            m_last[..m.len()].copy_from_slice(&m);
            m_last[m.len() - 1] = 0x80;

            for i in 0..Self::BLOCK_LEN {
                m_last[i] ^= self.cmac_k2[i];
                m_last[i] ^= x[i];
            }

            return self.cmac_cipher.encrypt(&m_last);
        }

        if len == Self::BLOCK_LEN {
            // M_n XOR K1;
            for i in 0..Self::BLOCK_LEN {
                x[i] ^= m[i] ^ self.cmac_k1[i];
            }

            return self.cmac_cipher.encrypt(&x);
        }

        if len > Self::BLOCK_LEN {
            let (last_block, blocks) = if r == 0 {
                (&m[m.len() - Self::BLOCK_LEN..], &m[..m.len() - Self::BLOCK_LEN])
            } else {
                (&m[m.len() - r..], &m[..m.len() - r])
            };

            for chunk in blocks.chunks_exact(Self::BLOCK_LEN) {
                // Y := X XOR M_i;
                // X := AES-128(K,Y);
                for i in 0..Self::BLOCK_LEN {
                    x[i] ^= chunk[i];
                }
                self.cmac_cipher.encrypt(&mut x);
            }

            if r == 0 {
                // M_n XOR K1;
                for i in 0..last_block.len() {
                    x[i] ^= last_block[i] ^ self.cmac_k1[i];
                }
                return self.cmac_cipher.encrypt(&mut x);
            } else {
                // M_last := padding(M_n) XOR K2;
                for i in 0..last_block.len() {
                    x[i] ^= last_block[i] ^ self.cmac_k2[i];
                }
                return self.cmac_cipher.encrypt(&mut x);
            }
        }
    }

    #[inline]
    fn siv(&self, components: &[&[u8]], payload: &[u8]) -> [u8; Self::BLOCK_LEN] {
        // 2.4.  S2V
        // https://tools.ietf.org/html/rfc5297#section-2.4
        // 
        // S2V(K, S1, ..., Sn) {
        //     if n = 0 then
        //         return V = AES-CMAC(K, <one>)
        //     fi
        //     D = AES-CMAC(K, <zero>)
        //     for i = 1 to n-1 do
        //         D = dbl(D) xor AES-CMAC(K, Si)
        //     done
        //     if len(Sn) >= 128 then
        //         T = Sn xorend D
        //     else
        //         T = dbl(D) xor pad(Sn)
        //     fi
        //     return V = AES-CMAC(K, T)
        // }

        // a vector of associated data AD[ ] where the number 
        // of components in the vector is not greater than 126
        // https://tools.ietf.org/html/rfc5297#section-2.6
        assert!(components.len() < 126);

        if components.is_empty() && payload.is_empty() {
            // indicates a string that is 127 zero bits concatenated with a
            // single one bit, that is 0^127 || 1^1.
            const ONE: [u8; Self::BLOCK_LEN] = 1u128.to_be_bytes();
            return self.cmac(&ONE);
        }

        // indicates a string that is 128 zero bits.
        const ZERO: [u8; Self::BLOCK_LEN] = [0u8; Self::BLOCK_LEN];
        let mut d = self.cmac(&ZERO);
        for aad in components.iter() {
            // assert_eq!(aad.len(), Self::BLOCK_LEN);
            let d1 = dbl(u128::from_be_bytes(d.clone())).to_be_bytes();
            let d2 = self.cmac(aad);
            for i in 0..Self::BLOCK_LEN {
                d[i] = d1[i] ^ d2[i];
            }
        }

        if payload.len() == Self::BLOCK_LEN {
            for i in 0..Self::BLOCK_LEN {
                d[i] ^= payload[i];
            }
            return self.cmac(&d);
        } else if payload.len() > Self::BLOCK_LEN {
            // T = Sn xorend D
            // leftmost(A, len(A)-len(B)) || (rightmost(A, len(B)) xor B)
            let n = payload.len() - Self::BLOCK_LEN;
            
            // TODO: 消除 Alloc.
            let mut p = payload.to_vec();

            let a = &mut p[n..n + Self::BLOCK_LEN];
            for i in 0..Self::BLOCK_LEN {
                a[i] ^= d[i];
            }

            return self.cmac(&p);
        } else {
            // T = dbl(D) xor pad(Sn)
            let mut t = dbl(u128::from_be_bytes(d)).to_be_bytes();
            for i in 0..payload.len() {
                t[i] ^= payload[i];
            }
            t[payload.len()] ^= 0b1000_0000;
            for i in payload.len() + 1..Self::BLOCK_LEN {
                // many 0 bits
                t[i] ^= 0;
            }

            return self.cmac(&t);
        }
    }

    #[inline]
    fn ctr_incr(&self, counter_block: &mut [u8; Self::BLOCK_LEN]) {
        let n = u128::from_be_bytes(*counter_block).wrapping_add(1).to_be_bytes();
        counter_block.copy_from_slice(&n);
    }

    pub fn encrypt(&self, components: &[&[u8]], plaintext_and_ciphertext: &mut [u8]) -> [u8; Self::BLOCK_LEN] {
        // 2.6.  SIV Encrypt
        // https://tools.ietf.org/html/rfc5297#section-2.6
        // 
        // SIV-ENCRYPT(K, P, AD1, ..., ADn) {
        //     K1 = leftmost(K, len(K)/2)
        //     K2 = rightmost(K, len(K)/2)
        //     V = S2V(K1, AD1, ..., ADn, P)
        //     Q = V bitand (1^64 || 0^1 || 1^31 || 0^1 || 1^31)
        //     m = (len(P) + 127)/128
        // 
        //     for i = 0 to m-1 do
        //        Xi = AES(K2, Q+i)
        //     done
        //     X = leftmost(X0 || ... || Xm-1, len(P))
        //     C = P xor X
        // 
        //     return V || C
        // }

        // V = S2V(K1, AD1, ..., ADn, P)
        let v = self.siv(components, &plaintext_and_ciphertext);
        // Q = V bitand (1^64 || 0^1 || 1^31 || 0^1 || 1^31)
        const V1: [u8; Self::BLOCK_LEN] = [
            // 1^64
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
            0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 
        ];
        let mut q = v.clone();
        for i in 0..Self::BLOCK_LEN {
            q[i] &= V1[i];
        }

        // CTR Counter
        let mut counter = u128::from_be_bytes(q);

        // m = (len(P) + 127)/128
        for chunk in plaintext_and_ciphertext.chunks_mut(Self::BLOCK_LEN) {
            let mut output_block = counter.clone().to_be_bytes();
            self.cipher.encrypt(&mut output_block);
            for i in 0..chunk.len() {
                chunk[i] ^= output_block[i];
            }

            counter = counter.wrapping_add(1);
        }

        v
    }

    pub fn decrypt(&self, components: &[&[u8]], iv: &[u8; Self::BLOCK_LEN], ciphertext_and_plaintext: &mut [u8]) {
        // 2.7.  SIV Decrypt
        // https://tools.ietf.org/html/rfc5297#section-2.7
        // 
        // SIV-DECRYPT(K, Z, AD1, ..., ADn) {
        //     V = leftmost(Z, 128)
        //     C = rightmost(Z, len(Z)-128)
        //     K1 = leftmost(K, len(K)/2)
        //     K2 = rightmost(K, len(K)/2)
        //     Q = V bitand (1^64 || 0^1 || 1^31 || 0^1 || 1^31)
        // 
        //     m = (len(C) + 127)/128
        //     for i = 0 to m-1 do
        //         Xi = AES(K2, Q+i)
        //     done
        //     X = leftmost(X0 || ... || Xm-1, len(C))
        //     P = C xor X
        //     T = S2V(K1, AD1, ..., ADn, P)
        // 
        //     if T = V then
        //         return P
        //     else
        //         return FAIL
        //     fi
        // }
        const V1: [u8; Self::BLOCK_LEN] = [
            // 1^64
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
            0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 
        ];

        let v = iv;

        let mut q = v.clone();
        for i in 0..Self::BLOCK_LEN {
            q[i] &= V1[i];
        }

        // CTR Counter
        let mut counter = u128::from_be_bytes(q);

        for chunk in ciphertext_and_plaintext.chunks_mut(Self::BLOCK_LEN) {
            let mut output_block = counter.clone().to_be_bytes();
            self.cipher.encrypt(&mut output_block);
            for i in 0..chunk.len() {
                chunk[i] ^= output_block[i];
            }

            counter = counter.wrapping_add(1);
        }

        // T = S2V(K1, AD1, ..., ADn, P)
        let plaintext = &ciphertext_and_plaintext;
        let t = self.siv(components, &plaintext);

        // Verify
        let is_match = bool::from(subtle::ConstantTimeEq::ct_eq(&t[..], &v));

        if !is_match {
            panic!("TagMisMatch ...");
        }
    }
}