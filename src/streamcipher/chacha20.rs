use crate::mem::Zeroize;


//    cccccccc  cccccccc  cccccccc  cccccccc
//    kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
//    kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
//    bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
// 
// c=constant k=key b=blockcount n=nonce

/// ChaCha20 for IETF Protocols
#[derive(Clone)]
pub struct Chacha20 {
    // constants | key | counter | nonce
    initial_state: [u32; 16],
    state: [u32; 16],
    keystream: [u8; Self::BLOCK_LEN],
    // keystream bytes used
    offset: usize,
}

impl Zeroize for Chacha20 {
    fn zeroize(&mut self) {
        self.initial_state.zeroize();
        self.state.zeroize();
        self.keystream.zeroize();
        self.offset.zeroize();
    }
}

impl Drop for Chacha20 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for Chacha20 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Chacha20").finish()
    }
}

impl Chacha20 {
    pub const KEY_LEN: usize   = 32;
    pub const BLOCK_LEN: usize = 64;
    pub const NONCE_LEN: usize = 12;
    
    const INITIAL_STATE: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]; // b"expand 32-byte k";

    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        // o  A 256-bit key
        // o  A 32-bit initial counter.
        // o  A 96-bit nonce. 
        // o  An arbitrary-length plaintext
        assert_eq!(key.len(), Self::KEY_LEN);
        assert_eq!(nonce.len(), Self::NONCE_LEN);

        let mut state = [0u32; 16];

        // The ChaCha20 state is initialized as follows:
        state[0] = Self::INITIAL_STATE[0];
        state[1] = Self::INITIAL_STATE[1];
        state[2] = Self::INITIAL_STATE[2];
        state[3] = Self::INITIAL_STATE[3];
        
        // A 256-bit key (32 Bytes)
        state[ 4] = u32::from_le_bytes([key[ 0], key[ 1], key[ 2], key[ 3]]);
        state[ 5] = u32::from_le_bytes([key[ 4], key[ 5], key[ 6], key[ 7]]);
        state[ 6] = u32::from_le_bytes([key[ 8], key[ 9], key[10], key[11]]);
        state[ 7] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
        state[ 8] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
        state[ 9] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
        state[10] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
        state[11] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);

        // Block counter (32 bits)
        state[12] = 0;

        // A 96-bit nonce. (12 Bytes)
        state[13] = u32::from_le_bytes([nonce[ 0], nonce[ 1], nonce[ 2], nonce[ 3]]);
        state[14] = u32::from_le_bytes([nonce[ 4], nonce[ 5], nonce[ 6], nonce[ 7]]);
        state[15] = u32::from_le_bytes([nonce[ 8], nonce[ 9], nonce[10], nonce[11]]);

        let mut keystream = [0u8; Self::BLOCK_LEN];
        state_to_keystream(&state, &mut keystream);

        Self { state, initial_state: state, keystream, offset: 0usize }
    }

    #[inline]
    fn incr(&mut self) {
        let mut state = self.initial_state.clone();
        
        // 20 rounds (diagonal rounds)
        diagonal_rounds(&mut state);
        
        for i in 0..16 {
            state[i] = state[i].wrapping_add(self.initial_state[i]);
        }

        // Block counter
        self.initial_state[12] = self.initial_state[12].wrapping_add(1);

        self.state = state;
        state_to_keystream(&self.state, &mut self.keystream);
        self.offset = 0;
    }

    pub fn encrypt_slice(&mut self, plaintext_and_ciphertext: &mut [u8]) {
        let plen = plaintext_and_ciphertext.len();
        for i in 0..plen {
            if self.offset == Self::BLOCK_LEN {
                self.incr();
            }

            plaintext_and_ciphertext[i] ^= self.keystream[self.offset];
            self.offset += 1;
        }
    }

    pub fn decrypt_slice(&mut self, ciphertext_and_plaintext: &mut [u8]) {
        let clen = ciphertext_and_plaintext.len();
        for i in 0..clen {
            if self.offset == Self::BLOCK_LEN {
                self.incr();
            }

            ciphertext_and_plaintext[i] ^= self.keystream[self.offset];
            self.offset += 1;
        }
    }
}

/// 2.1.  The ChaCha Quarter Round
// https://tools.ietf.org/html/rfc8439#section-2.1
#[inline]
fn quarter_round(state: &mut [u32], ai: usize, bi: usize, ci: usize, di: usize) {
    // n <<<= m
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
fn diagonal_rounds(state: &mut [u32]) {
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

#[inline]
fn state_to_keystream(state: &[u32; 16], keystream: &mut [u8; Chacha20::BLOCK_LEN]) {
    keystream[ 0.. 4].copy_from_slice(&state[0].to_le_bytes());
    keystream[ 4.. 8].copy_from_slice(&state[1].to_le_bytes());
    keystream[ 8..12].copy_from_slice(&state[2].to_le_bytes());
    keystream[12..16].copy_from_slice(&state[3].to_le_bytes());
    keystream[16..20].copy_from_slice(&state[4].to_le_bytes());
    keystream[20..24].copy_from_slice(&state[5].to_le_bytes());
    keystream[24..28].copy_from_slice(&state[6].to_le_bytes());
    keystream[28..32].copy_from_slice(&state[7].to_le_bytes());
    keystream[32..36].copy_from_slice(&state[8].to_le_bytes());
    keystream[36..40].copy_from_slice(&state[9].to_le_bytes());
    keystream[40..44].copy_from_slice(&state[10].to_le_bytes());
    keystream[44..48].copy_from_slice(&state[11].to_le_bytes());
    keystream[48..52].copy_from_slice(&state[12].to_le_bytes());
    keystream[52..56].copy_from_slice(&state[13].to_le_bytes());
    keystream[56..60].copy_from_slice(&state[14].to_le_bytes());
    keystream[60..64].copy_from_slice(&state[15].to_le_bytes());
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
    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
    
    // encrypt
    let mut chacha20 = Chacha20::new(&key, &nonce);

    let mut zero_block = [0u8; Chacha20::BLOCK_LEN];
    chacha20.encrypt_slice(&mut zero_block); // Block Index: 1
    chacha20.encrypt_slice(&mut zero_block); // Block Index: 2
    
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
    let mut ciphertext = plaintext.to_vec();
    chacha20.encrypt_slice(&mut ciphertext);
    assert_eq!(&ciphertext[..], &expected_ciphertext[..]);
}
