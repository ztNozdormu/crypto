use crate::blockcipher::BlockCipher;
use crate::streamcipher::StreamCipher;
use crate::aeadcipher::AeadCipher;


pub fn encrypt_block<C: BlockCipher>(key: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]) {
    C::encrypt_block_oneshot(key, plaintext_in_and_ciphertext_out)
}
pub fn decrypt_block<C: BlockCipher>(key: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) {
    C::decrypt_block_oneshot(key, ciphertext_in_and_plaintext_out)
}

pub fn encrypt_slice<C: StreamCipher>(key: &[u8], nonce: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]) {
    C::encrypt_slice_oneshot(key, nonce, plaintext_in_and_ciphertext_out)
}
pub fn decrypt_slice<C: StreamCipher>(key: &[u8], nonce: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) {
    C::decrypt_slice_oneshot(key, nonce, ciphertext_in_and_plaintext_out)
}

pub fn ae_encrypt_slice<C: AeadCipher>(key: &[u8], 
                                       nonce: &[u8], 
                                       plaintext_in_and_ciphertext_out: &mut [u8]) {
    aead_encrypt_slice::<C>(key, nonce, &[], plaintext_in_and_ciphertext_out)
}
pub fn ae_decrypt_slice<C: AeadCipher>(key: &[u8], 
                                       nonce: &[u8], 
                                       ciphertext_in_and_plaintext_out: &mut [u8]
) -> bool {
    aead_decrypt_slice::<C>(key, nonce, &[], ciphertext_in_and_plaintext_out)
}

pub fn aead_encrypt_slice<C: AeadCipher>(key: &[u8], 
                                         nonce: &[u8], 
                                         aad: &[u8], 
                                         plaintext_in_and_ciphertext_out: &mut [u8]) {
    C::aead_encrypt_slice_oneshot(key, nonce, aad, plaintext_in_and_ciphertext_out)
}
pub fn aead_decrypt_slice<C: AeadCipher>(key: &[u8],
                                         nonce: &[u8], 
                                         aad: &[u8], 
                                         ciphertext_in_and_plaintext_out: &mut [u8]
) -> bool {
    C::aead_decrypt_slice_oneshot(key, nonce, aad, ciphertext_in_and_plaintext_out)
}