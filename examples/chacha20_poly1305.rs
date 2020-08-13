extern crate crypto;

use crypto::chacha20::Chacha20;
use crypto::chacha20_poly1305::Chacha20Poly1305Ietf;
use crypto::poly1305::POLY1305_TAG_LEN;
use crypto::poly1305::POLY1305_BLOCK_LEN;


fn main() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 
        0x00, 0x00, 0x00, 0x00, 
    ];
    let plaintext = [1u8; 64];
    let aad = [1u8; POLY1305_BLOCK_LEN];
    
    let mut chacha20_poly1305 = Chacha20Poly1305Ietf::new(&key, &nonce, &aad);
    let mut tag = [0u8; POLY1305_TAG_LEN];
    let mut ciphertext = plaintext.clone();
    chacha20_poly1305.encrypt(&plaintext, &mut ciphertext[..], &mut tag[..]);
    
    println!("plaintext: {:?}", &plaintext[..]);
    println!("ciphertext: {:?}", &ciphertext[..]);
    println!("tag: {:?}", &tag[..]);
}
