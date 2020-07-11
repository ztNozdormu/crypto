use crate::chacha20::{ Chacha20, KEY_LEN, NONCE_LEN, BLOCK_LEN };
use crate::poly1305::{ Poly1305, POLY1305_KEY_LEN, POLY1305_BLOCK_LEN, POLY1305_TAG_LEN };

use subtle;
use byteorder::{LE, ByteOrder};

use std::convert::TryFrom;

// Chacha20 and Poly1305 Algorithm
// 
// Qround(state, ai, bi, ci, di):
//     a = state[ai];
//     b = state[bi];
//     c = state[ci];
//     d = state[di];
//     a += b; d ^= a; d <<<= 16;
//     c += d; b ^= c; b <<<= 12;
//     a += b; d ^= a; d <<<= 8;
//     c += d; b ^= c; b <<<= 7;
// end
// 
// inner_block(state):
//     Qround(state, 0, 4, 8, 12)
//     Qround(state, 1, 5, 9, 13)
//     Qround(state, 2, 6, 10, 14)
//     Qround(state, 3, 7, 11, 15)
//     Qround(state, 0, 5, 10, 15)
//     Qround(state, 1, 6, 11, 12)
//     Qround(state, 2, 7, 8, 13)
//     Qround(state, 3, 4, 9, 14)
// end
// 
// chacha20_block(key, counter, nonce):
//     state = constants | key | counter | nonce
//     initial_state = state
//     for i=1 upto 10
//         inner_block(state)
//     end
//     state += initial_state
//     return serialize(state)
// end
// 
// poly1305_key_gen(key,nonce):
//     counter = 0
//     block = chacha20_block(key,counter,nonce)
//     return block[0..31]
// end
// 
// clamp(r): r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
// poly1305_mac(msg, key):
//     r = le_bytes_to_num(key[0..15])
//     clamp(r)
//     s = le_bytes_to_num(key[16..31])
//     a = 0  /* a is the accumulator */
//     p = (1<<130)-5
//     for i=1 upto ceil(msg length in bytes / 16)
//         n = le_bytes_to_num(msg[((i-1)*16)..(i*16)] | [0x01])
//         a += n
//         a = (r * a) % p
//         end
//     a += s
//     return num_to_16_le_bytes(a)
// end
// 
// 
// pad16(x):
//     if (len(x) % 16)==0
//         then return NULL
//     else return copies(0, 16-(len(x)%16))
// end
// 
// chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
//     nonce = constant | iv
//     otk = poly1305_key_gen(key, nonce)
//     ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
//     mac_data = aad | pad16(aad)
//     mac_data |= ciphertext | pad16(ciphertext)
//     mac_data |= num_to_8_le_bytes(aad.length)
//     mac_data |= num_to_8_le_bytes(ciphertext.length)
//     tag = poly1305_mac(mac_data, otk)
//     return (ciphertext, tag)
// end


/// ChaCha20 and Poly1305 for IETF Protocols
/// https://tools.ietf.org/html/rfc8439
#[derive(Debug, Clone)]
pub struct Chacha20Poly1305Ietf {
    chacha20: Chacha20,
    aad: Vec<u8>,
    aad_len: usize,
    poly1305_key: [u8; POLY1305_KEY_LEN],
    data_len: usize,
}

impl Chacha20Poly1305Ietf {
    pub fn new(key: &[u8], nonce: &[u8], aad: &[u8]) -> Self {
        assert_eq!(key.len(), KEY_LEN);
        assert_eq!(nonce.len(), NONCE_LEN);            // 96-bit nonce
        assert_eq!(aad.len() % POLY1305_BLOCK_LEN, 0); // pad16

        let mut chacha20 = Chacha20::new(key, nonce, 0u32);
        chacha20.update_state();

        let keystream = chacha20.key_stream();

        chacha20.update_state();

        let mut poly1305_key = [0u8; POLY1305_KEY_LEN];
        poly1305_key.copy_from_slice(&keystream[..POLY1305_KEY_LEN][..]);

        Self { chacha20, data_len: 0, aad: aad.to_vec(), poly1305_key: poly1305_key, aad_len: aad.len() }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8], mac: &mut [u8]) {
        debug_assert!(ciphertext.len() >= ciphertext.len());
        assert!(mac.len() == POLY1305_TAG_LEN);

        self.chacha20.encrypt(plaintext, ciphertext);
        self.data_len += plaintext.len();

        let mut poly1305 = Poly1305::new(&self.poly1305_key[..]);
        poly1305.input(&self.aad);
        poly1305.input(&ciphertext);
        {
            let n = POLY1305_BLOCK_LEN - ciphertext.len() % POLY1305_BLOCK_LEN;
            if n > 0 {
                for _ in 0usize..n {
                    poly1305.input(&[0u8]);
                }
            }
        }
        
        let aad_len_bytes = u64::try_from(self.aad_len).unwrap().to_le_bytes();
        let ciphertext_len_bytes = u64::try_from(ciphertext.len()).unwrap().to_le_bytes();

        poly1305.input(&aad_len_bytes);
        poly1305.input(&ciphertext_len_bytes);

        let mac_digest = poly1305.mac();
        mac.copy_from_slice(&mac_digest);
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8], mac: &[u8]) -> bool {
        assert!(plaintext.len() >= ciphertext.len());

        let mut poly1305 = Poly1305::new(&self.poly1305_key[..]);

        poly1305.input(&self.aad);
        poly1305.input(ciphertext);
        {
            let n = POLY1305_BLOCK_LEN - ciphertext.len() % POLY1305_BLOCK_LEN;
            if n > 0 {
                for _ in 0usize..n {
                    poly1305.input(&[0u8]);
                }
            }
        }

        self.data_len += ciphertext.len();

        poly1305.input(&u64::try_from(self.aad_len).unwrap().to_le_bytes());
        poly1305.input(&u64::try_from(ciphertext.len()).unwrap().to_le_bytes());
        
        let mac_digest = poly1305.mac();

        // Verify
        if bool::from(subtle::ConstantTimeEq::ct_eq(&mac_digest[..], mac)) {
            self.chacha20.decrypt(ciphertext, plaintext);
            true
        } else {
            false
        }
    }
}


// chacha20-poly1305@openssh.com
// 
// http://bxr.su/OpenBSD/usr.bin/ssh/PROTOCOL.chacha20poly1305
// https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-03
// 
// Code:
// http://bxr.su/OpenBSD/usr.bin/ssh/chacha.c
// http://bxr.su/OpenBSD/usr.bin/ssh/chacha.h
// http://bxr.su/OpenBSD/usr.bin/ssh/poly1305.c
// http://bxr.su/OpenBSD/usr.bin/ssh/poly1305.h
// http://bxr.su/OpenBSD/usr.bin/ssh/cipher-chachapoly.c
// http://bxr.su/OpenBSD/usr.bin/ssh/cipher-chachapoly.h
// #[derive(Debug, Clone)]
// pub struct Chacha20Poly1305OpenSSH {
//     chacha20: Chacha20,
//     poly1305: Poly1305,
//     data_len: usize,
// }

#[test]
fn test_poly1305_key_generation() {
    // 2.6.2.  Poly1305 Key Generation Test Vector
    // https://tools.ietf.org/html/rfc8439#section-2.6.2
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 
        0x04, 0x05, 0x06, 0x07 
    ];

    let mut chacha20 = Chacha20::new(&key, &nonce, 0u32);
    chacha20.update_state();

    assert_eq!(&chacha20.key_stream()[..POLY1305_KEY_LEN], &[
        0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 
        0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2, 0x94, 0x71,
        0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5, 
        0x08, 0xdb, 0xb8, 0xe2, 0xfd, 0xd1, 0xa6, 0x46,
    ]);

    assert_eq!(chacha20.block_num(), 1u32);
}

#[test]
fn test_aead_chacha20_poly1305_encrypt() {
    // 2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305
    // https://tools.ietf.org/html/rfc8439#section-2.8.2
    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
    let aad: &[u8] = &[
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 
        0xc4, 0xc5, 0xc6, 0xc7,
                                0x00, 0x00, 0x00, 0x00, // Pad
    ];
    let key: &[u8] = &[
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce: &[u8] = &[
        0x07, 0x00, 0x00, 0x00,                         // Constants
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, // IV
    ];


    // Poly1305 one-time key
    let mut chacha20 = Chacha20::new(key, nonce, 0u32);
    assert_eq!(chacha20.state(), &[
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x83828180, 0x87868584, 0x8b8a8988, 0x8f8e8d8c,
        0x93929190, 0x97969594, 0x9b9a9998, 0x9f9e9d9c,
        0x00000000, 0x00000007, 0x43424140, 0x47464544,
    ]);
    chacha20.update_state();
    assert_eq!(chacha20.state(), &[
        0x252bac7b, 0xaf47b42d, 0x557ab609, 0x8455e9a4,
        0x73d6e10a, 0xebd97510, 0x7875932a, 0xff53d53e,
        0xdecc7ea2, 0xb44ddbad, 0xe49c17d1, 0xd8430bc9,
        0x8c94b7bc, 0x8b7d4b4b, 0x3927f67d, 0x1669a432,
    ]);
    assert_eq!(&chacha20.key_stream()[..POLY1305_KEY_LEN], &[
        0x7b, 0xac, 0x2b, 0x25, 0x2d, 0xb4, 0x47, 0xaf, 
        0x09, 0xb6, 0x7a, 0x55, 0xa4, 0xe9, 0x55, 0x84,
        0x0a, 0xe1, 0xd6, 0x73, 0x10, 0x75, 0xd9, 0xeb, 
        0x2a, 0x93, 0x75, 0x78, 0x3e, 0xd5, 0x53, 0xff,
    ]);

    let mut chacha20_poly1305 = Chacha20Poly1305Ietf::new(key, nonce, aad);
    // NOTE: 把手动对齐的数据长度除掉。
    chacha20_poly1305.aad_len = aad.len() - 4;
    let mut tag = [0u8; POLY1305_TAG_LEN];
    let mut ciphertext = [0u8; 114];
    chacha20_poly1305.encrypt(plaintext, &mut ciphertext[..], &mut tag[..]);
    assert_eq!(&ciphertext[..], &[
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    ][..]);
    assert_eq!(&tag[..], &[
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ]);
}

#[test]
fn test_aead_chacha20_poly1305_decrypt() {
    // A.5.  ChaCha20-Poly1305 AEAD Decryption
    // https://tools.ietf.org/html/rfc8439#appendix-A.5
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];
    let aad = [
        0xf3, 0x33, 0x88, 0x86, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x4e, 0x91,
                                0x00, 0x00, 0x00, 0x00, // Pad
    ];
    
    let plaintext = b"Internet-Drafts are draft documents valid for a \
maximum of six months and may be updated, replaced, or obsoleted \
by other documents at any time. It is inappropriate to use Internet-Drafts as \
reference material or to cite them other than as \x2f\xe2\x80\x9c\
work in progress.\x2f\xe2\x80\x9d\
";
    let mut chacha20_poly1305 = Chacha20Poly1305Ietf::new(&key, &nonce, &aad);
    // NOTE: 把手动对齐的数据长度除掉。
    chacha20_poly1305.aad_len = aad.len() - 4;
    let mut tag = [0u8; POLY1305_TAG_LEN];
    let mut ciphertext = [0u8; 265];
    chacha20_poly1305.encrypt(&plaintext[..], &mut ciphertext[..], &mut tag[..]);
    assert_eq!(&ciphertext[..], &[
        0x64, 0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4, 
        0x60, 0xf0, 0x62, 0xc7, 0x9b, 0xe6, 0x43, 0xbd,
        0x5e, 0x80, 0x5c, 0xfd, 0x34, 0x5c, 0xf3, 0x89, 
        0xf1, 0x08, 0x67, 0x0a, 0xc7, 0x6c, 0x8c, 0xb2,
        0x4c, 0x6c, 0xfc, 0x18, 0x75, 0x5d, 0x43, 0xee, 
        0xa0, 0x9e, 0xe9, 0x4e, 0x38, 0x2d, 0x26, 0xb0,
        0xbd, 0xb7, 0xb7, 0x3c, 0x32, 0x1b, 0x01, 0x00, 
        0xd4, 0xf0, 0x3b, 0x7f, 0x35, 0x58, 0x94, 0xcf,
        0x33, 0x2f, 0x83, 0x0e, 0x71, 0x0b, 0x97, 0xce, 
        0x98, 0xc8, 0xa8, 0x4a, 0xbd, 0x0b, 0x94, 0x81,
        0x14, 0xad, 0x17, 0x6e, 0x00, 0x8d, 0x33, 0xbd, 
        0x60, 0xf9, 0x82, 0xb1, 0xff, 0x37, 0xc8, 0x55,
        0x97, 0x97, 0xa0, 0x6e, 0xf4, 0xf0, 0xef, 0x61, 
        0xc1, 0x86, 0x32, 0x4e, 0x2b, 0x35, 0x06, 0x38,
        0x36, 0x06, 0x90, 0x7b, 0x6a, 0x7c, 0x02, 0xb0, 
        0xf9, 0xf6, 0x15, 0x7b, 0x53, 0xc8, 0x67, 0xe4,
        0xb9, 0x16, 0x6c, 0x76, 0x7b, 0x80, 0x4d, 0x46, 
        0xa5, 0x9b, 0x52, 0x16, 0xcd, 0xe7, 0xa4, 0xe9,
        0x90, 0x40, 0xc5, 0xa4, 0x04, 0x33, 0x22, 0x5e, 
        0xe2, 0x82, 0xa1, 0xb0, 0xa0, 0x6c, 0x52, 0x3e,
        0xaf, 0x45, 0x34, 0xd7, 0xf8, 0x3f, 0xa1, 0x15, 
        0x5b, 0x00, 0x47, 0x71, 0x8c, 0xbc, 0x54, 0x6a,
        0x0d, 0x07, 0x2b, 0x04, 0xb3, 0x56, 0x4e, 0xea, 
        0x1b, 0x42, 0x22, 0x73, 0xf5, 0x48, 0x27, 0x1a,
        0x0b, 0xb2, 0x31, 0x60, 0x53, 0xfa, 0x76, 0x99, 
        0x19, 0x55, 0xeb, 0xd6, 0x31, 0x59, 0x43, 0x4e,
        0xce, 0xbb, 0x4e, 0x46, 0x6d, 0xae, 0x5a, 0x10, 
        0x73, 0xa6, 0x72, 0x76, 0x27, 0x09, 0x7a, 0x10,
        0x49, 0xe6, 0x17, 0xd9, 0x1d, 0x36, 0x10, 0x94, 
        0xfa, 0x68, 0xf0, 0xff, 0x77, 0x98, 0x71, 0x30,
        0x30, 0x5b, 0xea, 0xba, 0x2e, 0xda, 0x04, 0xdf, 
        0x99, 0x7b, 0x71, 0x4d, 0x6c, 0x6f, 0x2c, 0x29,
        0xa6, 0xad, 0x5c, 0xb4, 0x02, 0x2b, 0x02, 0x70, 
        0x9b,
    ][..]);
    assert_eq!(&tag[..], &[
        0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb, 0x22, 
        0x39, 0x23, 0x36, 0xfe, 0xa1, 0x85, 0x1f, 0x38,
    ]);


    let mut chacha20_poly1305 = Chacha20Poly1305Ietf::new(&key, &nonce, &aad);
    // NOTE: 把手动对齐的数据长度除掉。
    chacha20_poly1305.aad_len = aad.len() - 4;

    let mut cleartext = [0u8; 265];
    let ret = chacha20_poly1305.decrypt(&ciphertext[..], &mut cleartext[..], &tag[..]);
    assert_eq!(ret, true);
    assert_eq!(&plaintext[..], &cleartext[..]);
}

// Appendix A.  Additional Test Vectors
// https://tools.ietf.org/html/rfc8439#appendix-A