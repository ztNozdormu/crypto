// Counter with CBC-MAC (CCM)
// https://tools.ietf.org/html/rfc3610
// 
// Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
// 
// CCM
// Counter with Cipher Block Chaining-Message Authentication Code. 
// 
// CBC-MAC
// Cipher Block Chaining-Message Authentication Code 

use crate::sm4::Sm4;
use crate::aes::{Aes128, Aes192, Aes256};
use crate::camellia::{Camellia128, Camellia192, Camellia256};

use subtle;

// Name  Description                               Size    Encoding
// ----  ----------------------------------------  ------  --------
// M     Number of octets in authentication field  3 bits  (M-2)/2
// L     Number of octets in length field          3 bits  L-1

// L    2 .. 8
// N    15-L octets
// m    0 <= l(m) < 2^(8L).
// a    0 <= l(a) < 2^64.

// Name  Description                          Size
// ----  -----------------------------------  -----------------------
// K     Block cipher key                     Depends on block cipher
// N     Nonce                                15-L octets
// m     Message to authenticate and encrypt  l(m) octets
// a     Additional authenticated data        l(a) octets


// AEAD_AES_128_CCM          // NONCE-LEN=12 TAG-LEN=16 Q=3
// AEAD_AES_128_CCM_8        // NONCE-LEN=12 TAG-LEN= 8 Q=3
// AEAD_AES_128_CCM_SHORT    // NONCE-LEN=11 TAG-LEN=16 Q=3
// AEAD_AES_128_CCM_SHORT_8  // NONCE-LEN=11 TAG-LEN= 8 Q=3
// AEAD_AES_128_CCM_SHORT_12 // NONCE-LEN=11 TAG-LEN=12 Q=3
#[derive(Debug, Clone)]
pub struct Aes128Ccm {
    cipher: Aes128,
    nonce: [u8; Self::NONCE_LEN],
}

// 6.  AES GCM Algorithms for Secure Shell
// https://tools.ietf.org/html/rfc5647#section-6
impl Aes128Ccm {
    pub const KEY_LEN: usize   = Aes128::KEY_LEN;
    pub const BLOCK_LEN: usize = Aes128::BLOCK_LEN;
    pub const NONCE_LEN: usize = 13;
    pub const TAG_LEN: usize   = 16;

    const P_MAX: usize = 16777215; // 2^24 - 1
    const A_MAX: u64   = u64::MAX; // 2^64 - 1
    const N_MIN: usize = 12;
    const N_MAX: usize = 12;
    // P_MAX + TAG_LEN
    const C_MAX: usize = 16777231; // 2^24 + 15
    const Q: usize     = 3;
    const L: usize     = 15 - Self::NONCE_LEN; // 3
    const N: usize     = Self::NONCE_LEN + 1;
    // 56 + 2 + 64
    const NON_AAD_FLAGS: u8 = 8 * (Self::TAG_LEN as u8 - 2) / 2 + (Self::L as u8 - 1);
    const AAD_FLAGS: u8     = Self::NON_AAD_FLAGS + 64;
    
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        assert_eq!(nonce.len(), Self::NONCE_LEN);

        let cipher = Aes128::new(key);

        let mut nonce2 = [0u8; Self::NONCE_LEN];
        nonce2.copy_from_slice(nonce);

        Self { cipher, nonce: nonce2 }
    }
    
    // CBC-Mac
    #[inline]
    fn cbc_mac(&self, aad: &[u8], data: &[u8]) -> [u8; Self::BLOCK_LEN] {
        let nonce = &self.nonce[..];

        let flags = if aad.is_empty() { Self::NON_AAD_FLAGS } else { Self::AAD_FLAGS };
        let max_len = (1 << (8 * Self::L as u128)) - 1;
        let max_len = core::cmp::min(max_len, core::usize::MAX as u128) as usize;
        assert!(data.len() <= max_len);
        
        let mut mac = [0u8; Self::BLOCK_LEN];

        let data_len_octets = data.len().to_be_bytes();
        
        let mut b0 = [0u8; Self::BLOCK_LEN];
        b0[0] = flags;
        let n = 1 + Self::NONCE_LEN;
        b0[1..n].copy_from_slice(&nonce);
        let q = data_len_octets.len() - Self::L;
        b0[n..].copy_from_slice(&data_len_octets[q..]);
        
        for i in 0..Self::BLOCK_LEN {
            mac[i] ^= b0[i];
            // NOTE: 重置以供后续使用
            b0[i] = 0;
        }
        self.cipher.encrypt(&mut mac);

        // associated data
        let alen = aad.len();
        let alen_octets = alen.to_be_bytes();
        let alen_octets_len = core::mem::size_of::<usize>();
        if alen > 0 {
            let mut n = 0usize;
            if alen < (1 << 16) - (1 << 8) {
                // alen < (1 << 16) - (1 << 8)
                // alen < 65280
                n = 2;
                b0[..2].copy_from_slice(&alen_octets[alen_octets_len - 2..]);
            } else if alen <= core::u32::MAX as usize {
                n = 6;

                b0[0] = 0xFF;
                b0[1] = 0xFE;
                b0[2..6].copy_from_slice(&alen_octets[alen_octets_len - 4..]);
            } else {
                n = 10;

                b0[0] = 0xFF;
                b0[1] = 0xFF;
                b0[2..10].copy_from_slice(&alen_octets[alen_octets_len - 8..]);
            }

            if b0.len() - n >= alen {
                b0[n..n + alen].copy_from_slice(aad);

                for i in 0..Self::BLOCK_LEN {
                    mac[i] ^= b0[i];
                }
                self.cipher.encrypt(&mut mac);
            } else {
                b0[n..].copy_from_slice(&aad[..Self::BLOCK_LEN - n]);

                for i in 0..Self::BLOCK_LEN {
                    mac[i] ^= b0[i];
                }
                self.cipher.encrypt(&mut mac);

                let data2 = &aad[b0.len() - n..];
                for chunk in data2.chunks(Self::BLOCK_LEN) {
                    for i in 0..chunk.len() {
                        mac[i] ^= chunk[i];
                    }
                    for i in chunk.len()..Self::BLOCK_LEN {
                        mac[i] ^= 0;
                    }
                    self.cipher.encrypt(&mut mac);
                }
            }
        }

        // Payload
        for chunk in data.chunks(Self::BLOCK_LEN) {
            for i in 0..chunk.len() {
                mac[i] ^= chunk[i];
            }
            for i in chunk.len()..Self::BLOCK_LEN {
                mac[i] ^= 0;
            }
            self.cipher.encrypt(&mut mac);
        }

        mac
    }

    // formatting function (encoding function)
    #[inline]
    fn gen_enc_block(&self, block: &mut [u8], block_idx: usize) {
        let n = 1 + Self::NONCE_LEN;

        block[0] = Self::L as u8 - 1;
        block[1..n].copy_from_slice(&self.nonce);

        let b = &mut block[n..];
        let block_idx_octets = block_idx.to_be_bytes();
        let block_idx_octets_len = core::mem::size_of::<usize>();

        let offset = block_idx_octets_len - b.len();
        b.copy_from_slice(&block_idx_octets[offset..]);
    }

    pub fn ae_encrypt(&mut self, plaintext_and_ciphertext: &mut [u8]) {
        debug_assert!(plaintext_and_ciphertext.len() > Self::TAG_LEN);

        let plen = plaintext_and_ciphertext.len() - Self::TAG_LEN;
        let plaintext = &plaintext_and_ciphertext[..plen];

        let mut mac = self.cbc_mac(&[], &plaintext);
        let mut counter_block = [0u8; Self::BLOCK_LEN];

        self.gen_enc_block(&mut counter_block, 0);
        self.cipher.encrypt(&mut counter_block);
        for i in 0..Self::BLOCK_LEN {
            mac[i] ^= counter_block[i];
        }
        
        let mut block_idx = 1usize;
        let plaintext = &mut plaintext_and_ciphertext[..plen];
        for chunk in plaintext.chunks_mut(Self::BLOCK_LEN) {
            self.gen_enc_block(&mut counter_block, block_idx);
            self.cipher.encrypt(&mut counter_block);
            for i in 0..chunk.len() {
                chunk[i] ^= counter_block[i];
            }

            block_idx += 1;
        }

        // NOTE: 追加 AUTH TAG数据至末尾。
        let tag = &mut plaintext_and_ciphertext[plen..plen + Self::TAG_LEN];
        tag.copy_from_slice(&mac[..Self::TAG_LEN]);
    }

    pub fn ae_decrypt(&mut self, ciphertext_and_plaintext: &mut [u8]) {
        let clen = ciphertext_and_plaintext.len() - Self::TAG_LEN;

        let mut counter_block = [0u8; Self::BLOCK_LEN];

        self.gen_enc_block(&mut counter_block, 0);
        self.cipher.encrypt(&mut counter_block);

        let b0 = counter_block.clone();

        let mut block_idx = 1usize;
        let ciphertext = &mut ciphertext_and_plaintext[..clen];
        for chunk in ciphertext.chunks_mut(Self::BLOCK_LEN) {
            self.gen_enc_block(&mut counter_block, block_idx);
            self.cipher.encrypt(&mut counter_block);
            for i in 0..chunk.len() {
                chunk[i] ^= counter_block[i];
            }
            block_idx += 1;
        }

        let plaintext = &ciphertext_and_plaintext[..clen];
        let mut mac = self.cbc_mac(&[], &plaintext);
        for i in 0..Self::BLOCK_LEN {
            mac[i] ^= b0[i];
        }

        let tag1 = &ciphertext_and_plaintext[clen..clen + Self::TAG_LEN];
        let tag2 = &mac[..Self::TAG_LEN];

        // Verify
        let is_match = bool::from(subtle::ConstantTimeEq::ct_eq(&tag1[..], &tag2));

        if !is_match {
            // NOTE: 清除数据？
            println!("AUTH TAG MISMATCH.");
        }
    }

    pub fn aead_encrypt(&mut self, aad: &[u8], plaintext_and_ciphertext: &mut [u8]) {
        todo!()
    }
    
    pub fn aead_decrypt(&mut self, aad: &[u8], ciphertext_and_plaintext: &mut [u8]) {
        todo!()
    }
}


#[test]
fn test_aes128_ccm() {
    let key = [0u8; Aes128Ccm::KEY_LEN];
    let nonce = [0u8; Aes128Ccm::NONCE_LEN];

    const PLEN: usize = 10;
    let mut plaintext = [1u8; Aes128Ccm::TAG_LEN + PLEN];
    for i in PLEN..plaintext.len() {
        plaintext[i] = 0;
    }

    let mut ciphertext = plaintext.clone();
    let mut cipher = Aes128Ccm::new(&key, &nonce);
    cipher.ae_encrypt(&mut ciphertext);

    let mut cleartext = ciphertext.clone();
    let mut cipher = Aes128Ccm::new(&key, &nonce);
    cipher.ae_decrypt(&mut cleartext);

    println!("plaintext: {:?}", &plaintext);
    println!("ciphertext: {:?}", &ciphertext);
    println!("cleartext: {:?}", &cleartext);

    assert_eq!(&cleartext[..PLEN], &plaintext[..PLEN]);
    assert_eq!(&ciphertext[PLEN..], &cleartext[PLEN..]);
}