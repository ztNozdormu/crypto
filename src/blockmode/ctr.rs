use crate::aes::generic::ExpandedKey128;


// 6.5 The Counter Mode, (Page-22)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
#[derive(Debug, Clone)]
pub struct Ctr {
    counter: u64,
    counter_block: [u8; 16],
}

impl Ctr {
    pub const NONCE_LEN: usize = 16;

    #[inline]
    pub fn new(nonce: &[u8]) -> Self {
        assert_eq!(nonce.len(), Self::NONCE_LEN);

        // NOTE: CTR 分组并没有一个统一的规范，在一些实现里面，它们的 Counter 可能是 32-Bits 的。
        //       比如 IPSecs: 
        // 
        //       4.  Counter Block Format
        //       https://tools.ietf.org/html/rfc3686#section-4
        let mut counter_block = [0u8; 16];
        counter_block[0..16].copy_from_slice(&nonce[..16]);

        let counter = u64::from_be_bytes([
            nonce[8], nonce[9], nonce[10], nonce[11], 
            nonce[12], nonce[13], nonce[14], nonce[15], 
        ]);

        Self { counter, counter_block, }
    }
    
    #[inline]
    pub fn counter(&self) -> u64 {
        self.counter
    }

    #[inline]
    pub fn set_counter(&mut self, counter: u64) {
        self.counter = counter;
        self.counter_block[8..16].copy_from_slice(&self.counter.to_be_bytes());
    }

    #[inline]
    pub fn incr(&mut self) {
        self.counter = self.counter.wrapping_add(1);
        self.counter_block[8..16].copy_from_slice(&self.counter.to_be_bytes());
    }

    #[inline]
    pub fn counter_block(&self) -> &[u8; 16] {
        &self.counter_block
    }
}

#[derive(Debug, Clone)]
pub struct AesCtr128 {
    ctr: Ctr,
    cipher: ExpandedKey128,
}

impl AesCtr128 {
    pub const BLOCK_LEN: usize = ExpandedKey128::BLOCK_LEN;
    pub const KEY_LEN: usize   = ExpandedKey128::KEY_LEN;
    pub const NONCE_LEN: usize = ExpandedKey128::BLOCK_LEN;

    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        assert_eq!(nonce.len(), Self::NONCE_LEN);

        let cipher = ExpandedKey128::new(key);
        let ctr = Ctr::new(nonce);
        
        Self { cipher, ctr }
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        for plaintext in data.chunks_mut(Self::BLOCK_LEN) {
            let counter_block = self.ctr.counter_block();
            let output_block = self.cipher.encrypt(&counter_block[..]);
            for i in 0..plaintext.len() {
                plaintext[i] ^= output_block[i];
            }
            self.ctr.incr();
        }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        for ciphertext in data.chunks_mut(Self::BLOCK_LEN) {
            let counter_block = self.ctr.counter_block();
            let output_block = self.cipher.encrypt(&counter_block[..]);
            for i in 0..ciphertext.len() {
                ciphertext[i] ^= output_block[i];
            }
            self.ctr.incr();
        }
    }
}



#[test]
fn test_aes128_ctr() {
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a").unwrap();

    let mut cipher = AesCtr128::new(&key, &nonce);
    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);

    let mut cipher = AesCtr128::new(&key, &nonce);
    let mut cleartext = ciphertext.clone();
    cipher.decrypt(&mut cleartext);

    assert_eq!(&cleartext[..], &plaintext[..]);
}

// F.5 CTR Example Vectors, (Page-62)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
#[test]
fn test_aes128_ctr_enc() {
    // F.5.1  CTR-AES128.Encrypt, (Page-62)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();

    let mut cipher = AesCtr128::new(&key, &nonce);

    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710").unwrap();

    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);

    assert_eq!(&ciphertext[..], &hex::decode("\
874d6191b620e3261bef6864990db6ce\
9806f66b7970fdff8617187bb9fffdff\
5ae4df3edbd5d35e5b4f09020db03eab\
1e031dda2fbe03d1792170a0f3009cee").unwrap()[..]);
}

#[test]
fn test_aes128_ctr_dec() {
    // F.5.2  CTR-AES128.Decrypt, (Page-63)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let nonce = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();

    let mut cipher = AesCtr128::new(&key, &nonce);

    let ciphertext = hex::decode("\
874d6191b620e3261bef6864990db6ce\
9806f66b7970fdff8617187bb9fffdff\
5ae4df3edbd5d35e5b4f09020db03eab\
1e031dda2fbe03d1792170a0f3009cee").unwrap();

    let mut plaintext = ciphertext.clone();
    cipher.decrypt(&mut plaintext);

    assert_eq!(&plaintext[..], &hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710").unwrap()[..]);
}