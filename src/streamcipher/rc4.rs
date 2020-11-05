// RC4 Source Code
// http://cypherpunks.venona.com/archive/1994/09/msg00304.html
// 
// https://en.wikipedia.org/wiki/RC4
use crate::mem::Zeroize;


const INIT_STATE: [u8; 256] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];


/// RC4 (Rivest Cipher 4 also known as ARC4 or ARCFOUR)
#[derive(Clone)]
pub struct Rc4 {
    x: u8,
    y: u8,
    state: [u8; 256],
}

impl Zeroize for Rc4 {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.state.iter_mut().zeroize();
    }
}

impl Drop for Rc4 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for Rc4 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Rc4").finish()
    }
}

impl Rc4 {
    pub const MIN_KEY_LEN: usize =   1; // In bytes
    pub const MAX_KEY_LEN: usize = 256; // In bytes


    pub fn new(key: &[u8]) -> Self {
        assert!(key.len() >= Self::MIN_KEY_LEN && key.len() <= Self::MAX_KEY_LEN);

        let key_len = key.len() as u8;
        let mut state = INIT_STATE;

        let mut index1 = 0u8;
        let mut index2 = 0u8;
        for counter in 0..256 {
            index2 = key[index1 as usize].wrapping_add(state[counter]).wrapping_add(index2);
            state.swap(counter as usize, index2 as usize);
            index1 = index1.wrapping_add(1) % key_len;
        }

        Self { x: 0, y: 0, state, }
    }

    #[inline]
    fn in_place(&mut self, data: &mut [u8]) {
        let mut xor_index = 0u8;

        for counter in 0..data.len() {
            self.x = self.x.wrapping_add(1);
            self.y = self.y.wrapping_add(self.state[self.x as usize] );

            self.state.swap(self.x as usize, self.y as usize);

            let a = self.state[self.x as usize];
            let b = self.state[self.y as usize];
            xor_index = a.wrapping_add(b);

            data[counter] ^= self.state[xor_index as usize];
        }
    }

    pub fn encrypt_slice(&mut self, plaintext_and_ciphertext: &mut [u8]) {
        self.in_place(plaintext_and_ciphertext);
    }
    
    pub fn decrypt_slice(&mut self, ciphertext_and_plaintext: &mut [u8]) {
        self.in_place(ciphertext_and_plaintext);
    }
}


#[test]
fn test_rc4() {
    // Test vectors
    // https://en.wikipedia.org/wiki/RC4#Test_vectors
    let key: &[u8] = b"Key";
    let mut rc4 = Rc4::new(&key);
    let plaintext = b"Plaintext";
    let mut ciphertext = plaintext.clone();
    rc4.encrypt_slice(&mut ciphertext);
    assert_eq!(&ciphertext[..],
        &hex::decode("BBF316E8D940AF0AD3").unwrap()[..]);

    let key: &[u8] = b"Wiki";
    let mut rc4 = Rc4::new(&key);
    let plaintext = b"pedia";
    let mut ciphertext = plaintext.clone();
    rc4.encrypt_slice(&mut ciphertext);
    assert_eq!(&ciphertext[..],
        &hex::decode("1021BF0420").unwrap()[..]);

    let key: &[u8] = b"Secret";
    let mut rc4 = Rc4::new(&key);
    let plaintext = b"Attack at dawn";
    let mut ciphertext = plaintext.clone();
    rc4.encrypt_slice(&mut ciphertext);
    assert_eq!(&ciphertext[..],
        &hex::decode("45A01F645FC35B383552544B9BF5").unwrap()[..]);

    // 2.  Test Vectors for RC4
    // https://tools.ietf.org/html/rfc6229#section-2
}
