use crate::poly1305::POLY1305_TAG_LEN;

use byteorder::{LE, ByteOrder};


pub const NONCE_LEN: usize = 12; // nonce length in bytes
pub const KEY_LEN: usize   = 32; // key length in bytes
pub const BLOCK_LEN: usize = 64; // block length in bytes

// maximum size of the plaintext is 274877906880 bytes, nearly 256 GB.
pub const P_MAX: usize = u32::MAX as usize * BLOCK_LEN;
// maximum size of the associated data is set to 2^64-1 octets by the length field for associated data.
// 18446744073709551615 octets
pub const A_MAX: u64 = u64::MAX;
pub const C_MAX: usize = P_MAX + POLY1305_TAG_LEN; // 274877906896 bytes


/// 2.1.  The ChaCha Quarter Round
// https://tools.ietf.org/html/rfc8439#section-2.1
#[inline]
pub fn quarter_round(state: &mut [u32], ai: usize, bi: usize, ci: usize, di: usize) {
    // n <<= m
    // 等介于: (n << m) ^ (n >> (32 - 8))

    // a += b; d ^= a; d <<<= 16;
    // c += d; b ^= c; b <<<= 12;
    // a += b; d ^= a; d <<<= 8;
    // c += d; b ^= c; b <<<= 7;
    let mut a = state[ai];
    let mut b = state[bi];
    let mut c = state[ci];
    let mut d = state[di];

    a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
    c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
    a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);
    c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);

    state[ai] = a;
    state[bi] = b;
    state[ci] = c;
    state[di] = d;
}

#[inline]
pub fn diagonal_rounds(state: &mut [u32]) {
    for _ in 0..10 {
        // column rounds
        quarter_round(state, 0, 4,  8, 12);
        quarter_round(state, 1, 5,  9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7,  8, 13);
        quarter_round(state, 3, 4,  9, 14);
    }
}

//    cccccccc  cccccccc  cccccccc  cccccccc
//    kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
//    kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
//    bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
// 
// c=constant k=key b=blockcount n=nonce
#[derive(Debug, Clone)]
pub struct Chacha20 {
    // constants | key | counter | nonce
    initial_state: [u32; 16],
    state: [u32; 16],
    // keystream_bytes_used
    block_seq: usize,
}

impl Chacha20 {
    pub fn new(key: &[u8], nonce: &[u8], block_num: u32) -> Self {
        // o  A 256-bit key
        // o  A 32-bit initial counter.
        // o  A 96-bit nonce. 
        // o  An arbitrary-length plaintext
        assert!(key.len() == KEY_LEN);
        assert!(nonce.len() == NONCE_LEN);

        let mut state = [0u32; 16];

        // The ChaCha20 state is initialized as follows:
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // A 256-bit key (32 Bytes)
        state[4] = LE::read_u32(&key[0..]);
        state[5] = LE::read_u32(&key[4..]);
        state[6] = LE::read_u32(&key[8..]);
        state[7] = LE::read_u32(&key[12..]);
        state[8] = LE::read_u32(&key[16..]);
        state[9] = LE::read_u32(&key[20..]);
        state[10] = LE::read_u32(&key[24..]);
        state[11] = LE::read_u32(&key[28..]);

        // Block counter (32 bits)
        state[12] = block_num;

        // A 96-bit nonce. (12 Bytes)
        state[13] = LE::read_u32(&nonce[0..]);
        state[14] = LE::read_u32(&nonce[4..]);
        state[15] = LE::read_u32(&nonce[8..]);

        Self { state, initial_state: state, block_seq: 0usize }
    }

    pub fn set_block_num(&mut self, block_num: u32) {
        self.initial_state[12] = block_num;
    }

    pub fn block_num(&self) -> u32 {
        self.initial_state[12]
    }

    pub fn initial_state(&self) -> &[u32; 16] {
        &self.initial_state
    }

    pub fn state(&self) -> &[u32; 16] {
        &self.state
    }
    
    // 2.3.  The ChaCha20 Block Function
    // https://tools.ietf.org/html/rfc8439#section-2.3
    pub fn update_state(&mut self) {
        let mut state = self.initial_state.clone();
        
        // 20 rounds (diagonal rounds)
        diagonal_rounds(&mut state);

        for i in 0..16 {
            state[i] = state[i].wrapping_add(self.initial_state[i]);
        }

        // Block counter
        // TODO: 也许就让它 panic 会更好？
        self.initial_state[12] = self.initial_state[12].wrapping_add(1);

        self.state = state;
    }

    pub fn key_stream(&self) -> [u8; BLOCK_LEN] {
        let mut stream = [0u8; BLOCK_LEN];
        stream[0..4].copy_from_slice(&self.state[0].to_le_bytes());
        stream[4..8].copy_from_slice(&self.state[1].to_le_bytes());
        stream[8..12].copy_from_slice(&self.state[2].to_le_bytes());
        stream[12..16].copy_from_slice(&self.state[3].to_le_bytes());
        stream[16..20].copy_from_slice(&self.state[4].to_le_bytes());
        stream[20..24].copy_from_slice(&self.state[5].to_le_bytes());
        stream[24..28].copy_from_slice(&self.state[6].to_le_bytes());
        stream[28..32].copy_from_slice(&self.state[7].to_le_bytes());
        stream[32..36].copy_from_slice(&self.state[8].to_le_bytes());
        stream[36..40].copy_from_slice(&self.state[9].to_le_bytes());
        stream[40..44].copy_from_slice(&self.state[10].to_le_bytes());
        stream[44..48].copy_from_slice(&self.state[11].to_le_bytes());
        stream[48..52].copy_from_slice(&self.state[12].to_le_bytes());
        stream[52..56].copy_from_slice(&self.state[13].to_le_bytes());
        stream[56..60].copy_from_slice(&self.state[14].to_le_bytes());
        stream[60..64].copy_from_slice(&self.state[15].to_le_bytes());
        stream
    }

    pub fn encrypt_block(&mut self, plaintext_block: &[u8], ciphertext_block: &mut [u8]) {
        debug_assert!(plaintext_block.len() == BLOCK_LEN);
        debug_assert!(ciphertext_block.len() >= BLOCK_LEN);
        assert!(self.block_seq == 0);

        self.update_state();
        let stream = self.key_stream();
        for j in 0..BLOCK_LEN {
            // NOTE: 可以使用 SIMD 中的 u8x64 来加速异或的步骤。
            ciphertext_block[j] = plaintext_block[j] ^ stream[j];
        }
    }

    pub fn decrypt_block(&mut self, ciphertext_block: &[u8], plaintext_block: &mut [u8]) {
        debug_assert!(ciphertext_block.len() == BLOCK_LEN);
        debug_assert!(plaintext_block.len() >= BLOCK_LEN);
        assert!(self.block_seq == 0);

        self.update_state();
        let stream = self.key_stream();
        for j in 0..BLOCK_LEN {
            plaintext_block[j] = ciphertext_block[j] ^ stream[j];
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
        debug_assert!(ciphertext.len() >= plaintext.len());

        let mut idx = 0usize;
        let mut stream = self.key_stream();
        loop {
            if self.block_seq == BLOCK_LEN {
                self.block_seq = 0;
                self.update_state();
                stream = self.key_stream();
            }

            if idx >= plaintext.len() {
                break;
            }

            ciphertext[idx] = plaintext[idx] ^ stream[self.block_seq];
            idx += 1;
            self.block_seq += 1;
        }
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) {
        debug_assert!(plaintext.len() >= ciphertext.len());

        let mut idx = 0usize;
        let mut stream = self.key_stream();
        loop {
            if self.block_seq == BLOCK_LEN {
                self.block_seq = 0;
                self.update_state();
                stream = self.key_stream();
            }

            if idx >= plaintext.len() {
                break;
            }

            plaintext[idx] = ciphertext[idx] ^ stream[self.block_seq];

            idx += 1;
            self.block_seq += 1;
        }
    }
}



#[test]
fn test_chacha20_qround() {
    // 2.1.1.  Test Vector for the ChaCha Quarter Round
    // https://tools.ietf.org/html/rfc8439#section-2.1.1
    let mut state = [0x11111111u32, 0x01020304, 0x9b8d6f43, 0x01234567];
    quarter_round(&mut state, 0, 1, 2, 3);
    assert_eq!(state, [0xea2a92f4u32, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]);
}

#[test]
fn test_chacha20_qround_on_the_chacha_state() {
    // 2.2.1.  Test Vector for the Quarter Round on the ChaCha State
    // https://tools.ietf.org/html/rfc8439#section-2.2.1
    let mut state: [u32; 16] = [
        0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
        0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
    ];
    let expected = [
        0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
        0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
    ];

    quarter_round(&mut state, 2, 7, 8, 13);

    assert_eq!(&state, &expected);
}

#[test]
fn test_chacha20_block() {
    // 2.3.2.  Test Vector for the ChaCha20 Block Function
    // https://tools.ietf.org/html/rfc8439#section-2.3.2
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 
        0x00, 0x00, 0x00, 0x00 
    ];
    let block_count = 1u32;

    let expected_state = [
        0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f,
        0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
        0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
        0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2,
    ];

    let expected_state2 = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
    ];

    let expected_keystream = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 
        0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 
        0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    ];
    
    let mut chacha20 = Chacha20::new(&key, &nonce, block_count);
    assert_eq!(chacha20.block_num(), 1u32);

    assert_eq!(chacha20.state(), &[
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000,
    ]);

    // After running 20 rounds (10 column rounds interleaved with 10 "diagonal rounds")
    let mut state = chacha20.initial_state().clone();
    diagonal_rounds(&mut state);
    assert_eq!(&state, &expected_state);

    // ChaCha state at the end of the ChaCha20 operation (matrix addition)
    chacha20.update_state();
    assert_eq!(chacha20.state(), &expected_state2);
    
    // After we serialize the state
    let keystream = chacha20.key_stream();
    assert_eq!(&keystream[..], &expected_keystream[..]);
}

#[test]
fn test_chacha20_cipher() {
    // 2.4.2.  Example and Test Vector for the ChaCha20 Cipher
    // https://tools.ietf.org/html/rfc8439#section-2.4.2
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 
        0x00, 0x00, 0x00, 0x00
    ];
    let block_count = 1u32;
    let plaintext = "Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

    let mut chacha20 = Chacha20::new(&key, &nonce, block_count);

    // First block after block operation
    chacha20.update_state();
    assert_eq!(chacha20.state(), &[
        0xf3514f22, 0xe1d91b40, 0x6f27de2f, 0xed1d63b8,
        0x821f138c, 0xe2062c3d, 0xecca4f7e, 0x78cff39e,
        0xa30a3b8a, 0x920a6072, 0xcd7479b5, 0x34932bed,
        0x40ba4c79, 0xcd343ec6, 0x4c2c21ea, 0xb7417df0,
    ]);
    let keystream1 = chacha20.key_stream();

    // Second block after block operation
    chacha20.update_state();
    assert_eq!(chacha20.state(), &[
        0x9f74a669, 0x410f633f, 0x28feca22, 0x7ec44dec,
        0x6d34d426, 0x738cb970, 0x3ac5e9f3, 0x45590cc4,
        0xda6e8b39, 0x892c831a, 0xcdea67c1, 0x2b7e1d90,
        0x037463f3, 0xa11a2073, 0xe8bcfb88, 0xedc49139,
    ]);
    let keystream2 = chacha20.key_stream();

    let expected_keystream: [u8; 114] = [
        0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1, 
        0x2f, 0xde, 0x27, 0x6f, 0xb8, 0x63, 0x1d, 0xed, 
        0x8c, 0x13, 0x1f, 0x82, 0x3d, 0x2c, 0x06, 0xe2, 
        0x7e, 0x4f, 0xca, 0xec, 0x9e, 0xf3, 0xcf, 0x78, 
        0x8a, 0x3b, 0x0a, 0xa3, 0x72, 0x60, 0x0a, 0x92, 
        0xb5, 0x79, 0x74, 0xcd, 0xed, 0x2b, 0x93, 0x34, 
        0x79, 0x4c, 0xba, 0x40, 0xc6, 0x3e, 0x34, 0xcd, 
        0xea, 0x21, 0x2c, 0x4c, 0xf0, 0x7d, 0x41, 0xb7, 
        0x69, 0xa6, 0x74, 0x9f, 0x3f, 0x63, 0x0f, 0x41, 
        0x22, 0xca, 0xfe, 0x28, 0xec, 0x4d, 0xc4, 0x7e, 
        0x26, 0xd4, 0x34, 0x6d, 0x70, 0xb9, 0x8c, 0x73, 
        0xf3, 0xe9, 0xc5, 0x3a, 0xc4, 0x0c, 0x59, 0x45, 
        0x39, 0x8b, 0x6e, 0xda, 0x1a, 0x83, 0x2c, 0x89, 
        0xc1, 0x67, 0xea, 0xcd, 0x90, 0x1d, 0x7e, 0x2b,
        0xf3, 0x63,
    ];
    assert_eq!(&keystream1[..], &expected_keystream[..64]);
    assert_eq!(&keystream2[..50], &expected_keystream[64..]);

    // encrypt
    let mut chacha20 = Chacha20::new(&key, &nonce, block_count);
    chacha20.update_state();
    let expected_ciphertext: [u8; 114] = [
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    ];
    let mut ciphertext = [0u8; 114];
    chacha20.encrypt(plaintext.as_bytes(), &mut ciphertext);
    assert_eq!(&ciphertext[..], &expected_ciphertext[..]);
}
