use crate::aes::Aes128;

// NOTE:
// 
// CFB 模式共有 4 子版本：
// 
//      1. CFB1,   the   1-bit CFB mode
//      2. CFB8,   the   8-bit CFB mode
//      3, CFB64,  the  64-bit CFB mode
//      4. CFB128, the 128-bit CFB mode
// 
// 这些 CFB 模式处理的数据需要按照 CFB_BIT_MODE（1/8/64/128） 来进行对齐。
// 考虑到，我们 API 接受的输入数据流为 Byte 序列，而 Byte 数据结构本身是一个
// 针对 Bit 对齐的数据结构。
// 所以在 CFB1 和 CFB8 这两种分组模式下，输入的数据流不需要处理对齐的情况。
// 但是 CFB64 和 CFB128 则需要 Byte 序列的长度分别按照 8 和 16 来进行对齐。
// 
// 综上，CFB1 和 CFB8 可以处理不定长的 Byte 序列，无需做对齐工作，
// 和 CTR/OFB 这些模式类似可以被设计为一个流密码算法。
// 
// CFB64 和 CFB128 这两个分组模式则跟 ECB 和 CBC 一样，还是只能在分组模式下工作，
// 成为一个块密码算法。
// 

// 6.3 The Cipher Feedback Mode, (Page-18)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
#[derive(Debug, Clone)]
pub struct AesCfb128 {
    // The number of bits in a data segment.
    s: usize,
    iv: [u8; Self::BLOCK_LEN],
    cipher: Aes128,
}

impl AesCfb128 {
    pub const BLOCK_LEN: usize = Aes128::BLOCK_LEN;
    pub const KEY_LEN: usize   = Aes128::KEY_LEN;
    pub const NONCE_LEN: usize = Aes128::BLOCK_LEN;
    pub const B: usize = Self::BLOCK_LEN * 8; // The block size, in bits.

    /// the 1-bit CFB mode
    pub const CFB1: usize   = 1;
    /// the 8-bit CFB mode
    pub const CFB8: usize   = 8;
    /// the 64-bit CFB mode
    pub const CFB64: usize  = 64;
    /// the 128-bit CFB mode
    pub const CFB128: usize = 128;

    pub fn new(key: &[u8], nonce: &[u8], mode: usize) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        assert_eq!(nonce.len(), Self::NONCE_LEN);
        // TODO: 目前只支持这两种模式
        assert!(mode == Self::CFB8 || mode == Self::CFB128);
        
        let cipher = Aes128::new(key);
        let mut iv = [0u8; Self::BLOCK_LEN];
        iv[..Self::BLOCK_LEN].copy_from_slice(nonce);
        
        Self { cipher, iv, s: mode }
    }

    // The number of bits in a data segment. 
    pub fn s(&self) -> usize {
        self.s
    }
    
    pub fn encrypt(&mut self, segments: &mut [u8]) {
        assert_eq!(segments.len() * 8 % self.s, 0);
        if segments.is_empty() {
            return ();
        }

        assert_eq!(self.s, 8);

        let mut last_input_block = self.iv.clone();
        let mut last_segment = 0u8;
        let n = segments.len() * 8 / self.s; // The number of data blocks or data segments in the plaintext.

        for j in 0..n {
            if j == 0 {
                let mut output_block = last_input_block.clone();
                self.cipher.encrypt(&mut output_block);
                segments[j] ^= output_block[0];
                last_segment = segments[j];
            } else {
                let mut tmp = [0u8; Self::BLOCK_LEN];
                tmp[0..Self::BLOCK_LEN - 1].copy_from_slice(&last_input_block[1..]);
                tmp[Self::BLOCK_LEN - 1] = last_segment;
                last_input_block = tmp;

                let mut output_block = last_input_block.clone();
                self.cipher.encrypt(&mut output_block);
                segments[j] ^= output_block[0];
                last_segment = segments[j];
            }
        }
    }

    pub fn decrypt(&mut self, segments: &mut [u8]) {
        assert_eq!(segments.len() * 8 % self.s, 0);
        if segments.is_empty() {
            return ();
        }

        assert_eq!(self.s, 8);

        let mut last_input_block = self.iv.clone();
        let mut last_segment = 0u8;
        let n = segments.len() * 8 / self.s; // The number of data blocks or data segments in the plaintext.
        for j in 0..n {
            if j == 0 {
                last_segment = segments[j];
                let mut output_block = last_input_block.clone();
                self.cipher.encrypt(&mut output_block);

                segments[j] ^= output_block[0];
            } else {
                let mut tmp = [0u8; Self::BLOCK_LEN];
                tmp[0..Self::BLOCK_LEN - 1].copy_from_slice(&last_input_block[1..]);
                tmp[Self::BLOCK_LEN - 1] = last_segment;
                last_input_block = tmp;

                last_segment = segments[j];
                let mut output_block = last_input_block.clone();
                self.cipher.encrypt(&mut output_block);
                segments[j] ^= output_block[0];
            }
        }
    }
}


#[test]
fn test_cfb8_aes128() {
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a").unwrap();

    let mut cipher = AesCfb128::new(&key, &nonce, AesCfb128::CFB8);
    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);

    let mut cipher = AesCfb128::new(&key, &nonce, AesCfb128::CFB8);
    let mut cleartext = ciphertext.clone();
    cipher.decrypt(&mut cleartext);

    assert_eq!(&cleartext[..], &plaintext[..]);
}

#[test]
fn test_cfb8_aes128_enc() {
    // F.3.7  CFB8-AES128.Encrypt, (Page-46)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = AesCfb128::new(&key, &nonce, AesCfb128::CFB8);

    let plaintext = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e];
    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);
    assert_eq!(&ciphertext[..], &[
        0x3b, 0x79, 0x42, 0x4c, 0x9c,
    ]);
}

#[test]
fn test_cfb8_aes128_dec() {
    // F.3.7  CFB8-AES128.Decrypt, (Page-48)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = AesCfb128::new(&key, &nonce, AesCfb128::CFB8);

    let ciphertext = [0x3b, 0x79, 0x42, 0x4c, 0x9c];
    let mut plaintext = ciphertext.clone();
    cipher.decrypt(&mut plaintext);
    assert_eq!(&plaintext[..], &[
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e
    ]);
}