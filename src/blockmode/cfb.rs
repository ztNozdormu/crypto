use crate::aes::{Aes128, Aes192, Aes256};
use crate::camellia::{Camellia128, Camellia192, Camellia256};

// 6.3 The Cipher Feedback Mode, (Page-18)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
// 
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


#[derive(Debug, Clone, Copy)]
struct Bits(pub u8);

impl Bits {
    pub fn bit(&self, pos: usize) -> bool {
        assert!(pos < 8);
        let pos = 8 - pos - 1;
        self.0 & 1 << pos != 0
    }

    pub fn set_bit(&mut self, pos: usize, val: bool) {
        assert!(pos < 8);
        let pos = 8 - pos - 1;
        self.0 ^= (0u8.wrapping_sub(val as u8) ^ self.0) & 1 << pos;
    }

    pub fn bit_xor(&mut self, pos: usize, other: u8) {
        let a = self.bit(pos);
        let b = Bits(other).bit(0);
        if a != b {
            self.set_bit(pos, true);
        } else {
            self.set_bit(pos, false);
        }
    }
}

fn left_shift_1(bytes: &mut [u8], bit: bool) {
    let mut last_bit = if bit { 0b0000_0001 } else { 0b0000_0000 };
    for byte in bytes.iter_mut().rev() {
        let b = (*byte & 0b1000_0000) >> 7;
        *byte <<= 1;
        *byte |= last_bit;
        last_bit = b;
    }
}

macro_rules! impl_block_cipher_with_cfb1_mode {
    ($name:tt, $cipher:tt) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            iv: [u8; Self::BLOCK_LEN],
            cipher: $cipher,
        }

        impl $name {
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const KEY_LEN: usize   = $cipher::KEY_LEN;
            pub const NONCE_LEN: usize = $cipher::BLOCK_LEN;
            pub const B: usize = Self::BLOCK_LEN * 8; // The block size, in bits.
            pub const S: usize = 1;                   // The number of bits in a data segment.

            pub fn new(key: &[u8], nonce: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);
                assert_eq!(nonce.len(), Self::NONCE_LEN);
                assert!(Self::S <= Self::B);
                assert!(Self::BLOCK_LEN <= 16);

                let cipher = $cipher::new(key);
                let mut iv = [0u8; Self::BLOCK_LEN];
                iv[..Self::BLOCK_LEN].copy_from_slice(nonce);
                
                Self { cipher, iv }
            }

            // The number of bits in a data segment. 
            pub fn s(&self) -> usize {
                Self::S
            }
            
            pub fn encrypt(&mut self, segments: &mut [u8]) {
                if segments.is_empty() {
                    return ();
                }

                let mut last_input_block = self.iv.clone();
                let mut last_segment = false;
                
                // First 8 data segment ( 1 byte )
                let mut output_block = last_input_block.clone();
                self.cipher.encrypt(&mut output_block);
                let mut first_byte = Bits(segments[0]);

                first_byte.bit_xor(0, output_block[0]);
                last_segment = first_byte.bit(0);

                segments[0] = first_byte.0;
                for i in 1..8 {
                    left_shift_1(&mut last_input_block, last_segment);

                    let mut output_block = last_input_block.clone();
                    self.cipher.encrypt(&mut output_block);
                    let mut byte = Bits(segments[0]);

                    byte.bit_xor(i, output_block[0]);
                    last_segment = byte.bit(i);
                    segments[0] = byte.0;
                }

                if segments.len() == 1 {
                    return ();
                }

                let data = &mut segments[1..];
                for byte in data.iter_mut() {
                    for i in 0..8 {
                        left_shift_1(&mut last_input_block, last_segment);

                        let mut output_block = last_input_block.clone();
                        self.cipher.encrypt(&mut output_block);

                        let mut bits = Bits(*byte);

                        bits.bit_xor(i, output_block[0]);
                        last_segment = bits.bit(i);
                        *byte = bits.0;
                    }
                }
            }

            pub fn decrypt(&mut self, segments: &mut [u8]) {
                if segments.is_empty() {
                    return ();
                }

                let mut last_input_block = self.iv.clone();
                let mut last_segment = false;
                
                // First 8 data segment ( 1 byte )
                let mut output_block = last_input_block.clone();
                self.cipher.encrypt(&mut output_block);
                let mut first_byte = Bits(segments[0]);

                last_segment = first_byte.bit(0);

                first_byte.bit_xor(0, output_block[0]);
                segments[0] = first_byte.0;

                for i in 1..8 {
                    left_shift_1(&mut last_input_block, last_segment);

                    let mut output_block = last_input_block.clone();
                    self.cipher.encrypt(&mut output_block);
                    let mut byte = Bits(segments[0]);
                    last_segment = byte.bit(i);

                    byte.bit_xor(i, output_block[0]);
                    segments[0] = byte.0;
                }

                if segments.len() == 1 {
                    return ();
                }
                
                let data = &mut segments[1..];
                for byte in data.iter_mut() {
                    for i in 0..8 {
                        left_shift_1(&mut last_input_block, last_segment);

                        let mut output_block = last_input_block.clone();
                        self.cipher.encrypt(&mut output_block);

                        let mut bits = Bits(*byte);
                        last_segment = bits.bit(i);

                        bits.bit_xor(i, output_block[0]);
                        *byte = bits.0;
                    }
                }
            }
        }
    }
}

macro_rules! impl_block_cipher_with_cfb8_mode {
    ($name:tt, $cipher:tt) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            iv: [u8; Self::BLOCK_LEN],
            cipher: $cipher,
        }

        impl $name {
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const KEY_LEN: usize   = $cipher::KEY_LEN;
            pub const NONCE_LEN: usize = $cipher::BLOCK_LEN;
            pub const B: usize = Self::BLOCK_LEN * 8; // The block size, in bits.
            pub const S: usize = 8;                   // The number of bits in a data segment.
            
            pub fn new(key: &[u8], nonce: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);
                assert_eq!(nonce.len(), Self::NONCE_LEN);
                assert!(Self::S <= Self::B);

                let cipher = $cipher::new(key);
                let mut iv = [0u8; Self::BLOCK_LEN];
                iv[..Self::BLOCK_LEN].copy_from_slice(nonce);
                
                Self { cipher, iv }
            }

            // The number of bits in a data segment. 
            pub fn s(&self) -> usize {
                Self::S
            }
            
            pub fn encrypt(&mut self, segments: &mut [u8]) {
                if segments.is_empty() {
                    return ();
                }

                let mut last_input_block = self.iv.clone();
                let mut last_segment = 0u8;

                // First data segment
                let mut output_block = last_input_block.clone();
                self.cipher.encrypt(&mut output_block);
                segments[0] ^= output_block[0];
                last_segment = segments[0];

                if segments.len() == 1 {
                    return ();
                }

                for segment in &mut segments[1..].iter_mut() {
                    let mut tmp = [0u8; Self::BLOCK_LEN];
                    tmp[0..Self::BLOCK_LEN - 1].copy_from_slice(&last_input_block[1..]);
                    tmp[Self::BLOCK_LEN - 1] = last_segment;
                    last_input_block = tmp;

                    let mut output_block = last_input_block.clone();
                    self.cipher.encrypt(&mut output_block);
                    *segment ^= output_block[0];
                    last_segment = *segment;
                }
            }

            pub fn decrypt(&mut self, segments: &mut [u8]) {
                if segments.is_empty() {
                    return ();
                }

                let mut last_input_block = self.iv.clone();
                let mut last_segment = 0u8;

                // First data segment
                last_segment = segments[0];
                let mut output_block = last_input_block.clone();
                self.cipher.encrypt(&mut output_block);
                segments[0] ^= output_block[0];

                if segments.len() == 1 {
                    return ();
                }

                for segment in &mut segments[1..].iter_mut() {
                    let mut tmp = [0u8; Self::BLOCK_LEN];
                    tmp[0..Self::BLOCK_LEN - 1].copy_from_slice(&last_input_block[1..]);
                    tmp[Self::BLOCK_LEN - 1] = last_segment;
                    last_input_block = tmp;

                    last_segment = *segment;
                    let mut output_block = last_input_block.clone();
                    self.cipher.encrypt(&mut output_block);
                    *segment ^= output_block[0];
                }
            }
        }
    }
}

macro_rules! impl_block_cipher_with_cfb64_mode {
    ($name:tt, $cipher:tt) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            iv: [u8; Self::BLOCK_LEN],
            cipher: $cipher,
        }

        impl $name {
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const KEY_LEN: usize   = $cipher::KEY_LEN;
            pub const NONCE_LEN: usize = $cipher::BLOCK_LEN;
            pub const B: usize = Self::BLOCK_LEN * 8; // The block size, in bits.
            pub const S: usize = 64;                  // The number of bits in a data segment.
            const SEGMENTS_LEN: usize = Self::S / 8; // 8 bytes

            pub fn new(key: &[u8], nonce: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);
                assert_eq!(nonce.len(), Self::NONCE_LEN);
                assert!(Self::S <= Self::B);

                let cipher = $cipher::new(key);
                let mut iv = [0u8; Self::BLOCK_LEN];
                iv[..Self::BLOCK_LEN].copy_from_slice(nonce);
                
                Self { cipher, iv }
            }

            // The number of bits in a data segment. 
            pub fn s(&self) -> usize {
                Self::S
            }
            
            pub fn encrypt(&mut self, segments: &mut [u8]) {
                assert_eq!(segments.len() * 8 % Self::S, 0);
                if segments.len() < Self::SEGMENTS_LEN {
                    return ();
                }

                let mut last_input_block = self.iv.clone();
                let mut last_segment = [0u8; Self::SEGMENTS_LEN]; // 8 Bytes

                // First segment data
                let mut output_block = last_input_block.clone();
                self.cipher.encrypt(&mut output_block);
                for i in 0..Self::SEGMENTS_LEN {
                    segments[i] ^= output_block[i];
                    last_segment[i]  = segments[i];
                }

                let data = &mut segments[Self::SEGMENTS_LEN..];
                for segment in data.chunks_mut(Self::SEGMENTS_LEN) {
                    let mut tmp = [0u8; Self::BLOCK_LEN];
                    tmp[0..Self::BLOCK_LEN - Self::SEGMENTS_LEN].copy_from_slice(&last_input_block[Self::SEGMENTS_LEN..]);
                    tmp[Self::BLOCK_LEN - Self::SEGMENTS_LEN..].copy_from_slice(&last_segment);
                    last_input_block = tmp;

                    let mut output_block = last_input_block.clone();
                    self.cipher.encrypt(&mut output_block);
                    for i in 0..Self::S / 8 {
                        segment[i] ^= output_block[i];
                        last_segment[i] = segment[i];
                    }
                }
            }

            pub fn decrypt(&mut self, segments: &mut [u8]) {
                assert_eq!(segments.len() * 8 % Self::S, 0);
                if segments.len() < Self::SEGMENTS_LEN {
                    return ();
                }

                let mut last_input_block = self.iv.clone();
                let mut last_segment = [0u8; Self::S / 8];

                // First segment data
                let mut output_block = last_input_block.clone();
                self.cipher.encrypt(&mut output_block);
                for i in 0..Self::SEGMENTS_LEN {
                    last_segment[i] = segments[i];
                    segments[i] ^= output_block[i];
                }

                let data = &mut segments[Self::SEGMENTS_LEN..];
                for segment in data.chunks_mut(Self::SEGMENTS_LEN) {
                    let mut tmp = [0u8; Self::BLOCK_LEN];
                    tmp[0..Self::BLOCK_LEN - Self::SEGMENTS_LEN].copy_from_slice(&last_input_block[Self::SEGMENTS_LEN..]);
                    tmp[Self::BLOCK_LEN - Self::SEGMENTS_LEN..].copy_from_slice(&last_segment);
                    last_input_block = tmp;

                    let mut output_block = last_input_block.clone();
                    self.cipher.encrypt(&mut output_block);
                    for i in 0..Self::S / 8 {
                        last_segment[i] = segment[i];
                        segment[i] ^= output_block[i];
                    }
                }
            }
        }
    }
}

macro_rules! impl_block_cipher_with_cfb128_mode {
    ($name:tt, $cipher:tt) => {
        #[derive(Debug, Clone)]
        pub struct $name {
            iv: [u8; Self::BLOCK_LEN],
            cipher: $cipher,
        }

        impl $name {
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const KEY_LEN: usize   = $cipher::KEY_LEN;
            pub const NONCE_LEN: usize = $cipher::BLOCK_LEN;
            pub const B: usize = Self::BLOCK_LEN * 8; // The block size, in bits.
            pub const S: usize = 128;                 // The number of bits in a data segment.


            pub fn new(key: &[u8], nonce: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);
                assert_eq!(nonce.len(), Self::NONCE_LEN);
                assert!(Self::S <= Self::B);

                let cipher = $cipher::new(key);
                let mut iv = [0u8; Self::BLOCK_LEN];
                iv[..Self::BLOCK_LEN].copy_from_slice(nonce);
                
                Self { cipher, iv }
            }

            // The number of bits in a data segment. 
            pub fn s(&self) -> usize {
                Self::S
            }
            
            pub fn encrypt(&mut self, segments: &mut [u8]) {
                assert_eq!(segments.len() * 8 % Self::S, 0);

                let mut last_input_block = self.iv.clone();

                for segment in segments.chunks_mut(Self::BLOCK_LEN) {
                    debug_assert_eq!(segment.len(), Self::BLOCK_LEN);

                    let mut output_block = last_input_block.clone();
                    self.cipher.encrypt(&mut output_block);

                    for i in 0..Self::BLOCK_LEN {
                        segment[i] ^= output_block[i];
                        last_input_block[i] = segment[i];
                    }
                }
            }

            pub fn decrypt(&mut self, segments: &mut [u8]) {
                assert_eq!(segments.len() * 8 % Self::S, 0);

                let mut last_input_block = self.iv.clone();

                for segment in segments.chunks_mut(Self::BLOCK_LEN) {
                    debug_assert_eq!(segment.len(), Self::BLOCK_LEN);

                    let mut output_block = last_input_block.clone();
                    for i in 0..Self::BLOCK_LEN {
                        last_input_block[i] = segment[i];
                    }

                    self.cipher.encrypt(&mut output_block);

                    for i in 0..Self::BLOCK_LEN {
                        segment[i] ^= output_block[i];
                    }
                }
            }
        }
    }
}

impl_block_cipher_with_cfb1_mode!(Aes128Cfb1, Aes128);
impl_block_cipher_with_cfb1_mode!(Aes192Cfb1, Aes192);
impl_block_cipher_with_cfb1_mode!(Aes256Cfb1, Aes256);
impl_block_cipher_with_cfb1_mode!(Camellia128Cfb1, Camellia128);
impl_block_cipher_with_cfb1_mode!(Camellia192Cfb1, Camellia192);
impl_block_cipher_with_cfb1_mode!(Camellia256Cfb1, Camellia256);

impl_block_cipher_with_cfb8_mode!(Aes128Cfb8, Aes128);
impl_block_cipher_with_cfb8_mode!(Aes192Cfb8, Aes192);
impl_block_cipher_with_cfb8_mode!(Aes256Cfb8, Aes256);
impl_block_cipher_with_cfb8_mode!(Camellia128Cfb8, Camellia128);
impl_block_cipher_with_cfb8_mode!(Camellia192Cfb8, Camellia192);
impl_block_cipher_with_cfb8_mode!(Camellia256Cfb8, Camellia256);

impl_block_cipher_with_cfb64_mode!(Aes128Cfb64, Aes128);
impl_block_cipher_with_cfb64_mode!(Aes192Cfb64, Aes192);
impl_block_cipher_with_cfb64_mode!(Aes256Cfb64, Aes256);
impl_block_cipher_with_cfb64_mode!(Camellia128Cfb64, Camellia128);
impl_block_cipher_with_cfb64_mode!(Camellia192Cfb64, Camellia192);
impl_block_cipher_with_cfb64_mode!(Camellia256Cfb64, Camellia256);

impl_block_cipher_with_cfb128_mode!(Aes128Cfb128, Aes128);
impl_block_cipher_with_cfb128_mode!(Aes192Cfb128, Aes192);
impl_block_cipher_with_cfb128_mode!(Aes256Cfb128, Aes256);
impl_block_cipher_with_cfb128_mode!(Camellia128Cfb128, Camellia128);
impl_block_cipher_with_cfb128_mode!(Camellia192Cfb128, Camellia192);
impl_block_cipher_with_cfb128_mode!(Camellia256Cfb128, Camellia256);


#[test]
fn test_aes128_cfb8() {
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a").unwrap();

    let mut cipher = Aes128Cfb8::new(&key, &nonce);
    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);

    let mut cipher = Aes128Cfb8::new(&key, &nonce);
    let mut cleartext = ciphertext.clone();
    cipher.decrypt(&mut cleartext);

    assert_eq!(&cleartext[..], &plaintext[..]);
}

#[test]
fn test_aes128_cfb64() {
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a8aae2d8a8a").unwrap();

    let mut cipher = Aes128Cfb64::new(&key, &nonce);
    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);

    let mut cipher = Aes128Cfb64::new(&key, &nonce);
    let mut cleartext = ciphertext.clone();
    cipher.decrypt(&mut cleartext);

    assert_eq!(&cleartext[..], &plaintext[..]);
}

#[test]
fn test_aes128_cfb1_enc() {
    // F.3.1  CFB1-AES128.Encrypt, (Page-36)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = Aes128Cfb1::new(&key, &nonce);
// 0110_1011_1100_0001
// 0110_1000_1011_0011
    let plaintext = [0x6b, 0xc1];
    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);
    assert_eq!(&ciphertext[..], &[ 0x68, 0xb3 ]);
}

#[test]
fn test_aes128_cfb1_dec() {
    // F.3.2  CFB1-AES128.Decrypt, (Page-37)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = Aes128Cfb1::new(&key, &nonce);

    let ciphertext = [0x68, 0xb3];
    let mut plaintext = ciphertext.clone();
    cipher.decrypt(&mut plaintext);
    assert_eq!(&plaintext[..], &[ 0x6b, 0xc1 ]);
}

#[test]
fn test_aes128_cfb8_enc() {
    // F.3.7  CFB8-AES128.Encrypt, (Page-46)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = Aes128Cfb8::new(&key, &nonce);

    let plaintext = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e];
    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);
    assert_eq!(&ciphertext[..], &[
        0x3b, 0x79, 0x42, 0x4c, 0x9c,
    ]);
}

#[test]
fn test_aes128_cfb8_dec() {
    // F.3.7  CFB8-AES128.Decrypt, (Page-48)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = Aes128Cfb8::new(&key, &nonce);

    let ciphertext = [0x3b, 0x79, 0x42, 0x4c, 0x9c];
    let mut plaintext = ciphertext.clone();
    cipher.decrypt(&mut plaintext);
    assert_eq!(&plaintext[..], &[
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e
    ]);
}

#[test]
fn test_aes128_cfb128_enc() {
    // F.3.13  CFB128-AES128.Encrypt, (Page-57)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = Aes128Cfb128::new(&key, &nonce);

    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710\
").unwrap();

    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);
    assert_eq!(&ciphertext[..], &hex::decode("\
3b3fd92eb72dad20333449f8e83cfb4a\
c8a64537a0b3a93fcde3cdad9f1ce58b\
26751f67a3cbb140b1808cf187a4f4df\
c04b05357c5d1c0eeac4c66f9ff7f2e6\
").unwrap()[..] );
}

#[test]
fn test_aes128_cfb128_dec() {
    // F.3.14  CFB128-AES128.Decrypt, (Page-57)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = Aes128Cfb128::new(&key, &nonce);

    let ciphertext = hex::decode("\
3b3fd92eb72dad20333449f8e83cfb4a\
c8a64537a0b3a93fcde3cdad9f1ce58b\
26751f67a3cbb140b1808cf187a4f4df\
c04b05357c5d1c0eeac4c66f9ff7f2e6\
").unwrap();

    let mut plaintext = ciphertext.clone();
    cipher.decrypt(&mut plaintext);
    assert_eq!(&plaintext[..], &hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710\
").unwrap()[..] );
}