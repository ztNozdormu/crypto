use crate::aes::generic;

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;


#[inline]
fn encrypt_aarch64(expanded_key: &[u8], nr: usize, plaintext: &mut [u8]) {
    debug_assert_eq!(plaintext.len(), 16);

    unsafe {
        let mut block: uint8x16_t = vld1q_u8(plaintext.as_ptr());
        
        block = vaeseq_u8(block, vld1q_u8(expanded_key.as_ptr()));
        // 9
        // 11
        // 13
        for i in 1..nr {
            // AES mix columns
            block = vaesmcq_u8(block);
            // AES single round encryption
            block = vaeseq_u8(block, vld1q_u8(expanded_key.as_ptr().offset( i * 16 )));
        }

        // Final Add (bitwise Xor)
        block = veorq_u8(block, vld1q_u8( expanded_key.as_ptr().offset( nr * 16 ) ));

        // vst1q_u8(output, block);
        union U {
            array: [u8; 16],
            vec: uint8x16_t,
        }

        let array = unsafe { U { vec: block }.array };
        plaintext[0..16].copy_from_slice(&array);
    }
}

#[inline]
fn decrypt_aarch64(expanded_key: &[u8], nr: usize, ciphertext: &mut [u8]) {
    debug_assert_eq!(ciphertext.len(), 16);

    unsafe {
        let mut block: uint8x16_t = vld1q_u8(ciphertext.as_ptr());

        block = veorq_u8(block, vld1q_u8( expanded_key.as_ptr().offset( nr * 16 ) ));

        for i in 1..nr {
            // AES single round decryption
            block = vaesdq_u8(block, vld1q_u8(expanded_key.as_ptr().offset( (nr - i) * 16 )));
            // AES inverse mix columns.
            block = vaesimcq_u8(block);
        }

        // AES single round decryption
        block = vaesdq_u8(block, vld1q_u8( expanded_key.as_ptr() ));

        // vst1q_u8(output, block);
        union U {
            array: [u8; 16],
            vec: uint8x16_t,
        }

        let array = unsafe { U { vec: block }.array };
        ciphertext[0..16].copy_from_slice(&array);
    }
}


#[derive(Debug, Clone)]
pub struct Aes128 {
    pub ek: [u8; (10 + 1) * Self::BLOCK_LEN],
}

impl Aes128 {
    pub const BLOCK_LEN: usize = 16;
    pub const KEY_LEN: usize   = 16;

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        let ek = generic::Aes128::new(key).ek;

        Self { ek }
    }
    
    pub fn encrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);
        
        encrypt_aarch64(&self.ek, 10, block);
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        debug_assert_eq!(block.len(), Self::BLOCK_LEN);

        decrypt_aarch64(&self.ek, 10, block);
    }
}
