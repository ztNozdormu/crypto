use crate::aes::generic::ExpandedKey128;


// NOTE:
// 
// ECB 和 CBC 分组模式都无法处理不定长的输入数据，
// 需要自己手动为不定长数据按照块密码算法的块大小做对齐工作。


// 6.1 The Electronic Codebook Mode, (Page-16)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
#[derive(Debug, Clone)]
pub struct AesEcb128 {
    cipher: ExpandedKey128,
}

impl AesEcb128 {
    pub const BLOCK_LEN: usize = ExpandedKey128::BLOCK_LEN;
    pub const KEY_LEN: usize   = ExpandedKey128::KEY_LEN;

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        let cipher = ExpandedKey128::new(key);

        Self { cipher }
    }
    
    /// the plaintext must be a sequence of one or more complete data blocks.
    /// the total number of bits in the plaintext must be a positive multiple 
    /// of the block (or segment) size.
    pub fn encrypt(&mut self, blocks: &mut [u8]) {
        assert_eq!(blocks.len() % Self::BLOCK_LEN, 0);

        for plaintext in blocks.chunks_mut(Self::BLOCK_LEN) {
            debug_assert_eq!(plaintext.len(), Self::BLOCK_LEN);

            let output_block = self.cipher.encrypt(&plaintext);
            
            for i in 0..Self::BLOCK_LEN {
                plaintext[i] = output_block[i];
            }
        }
    }

    /// the plaintext must be a sequence of one or more complete data blocks.
    /// the total number of bits in the plaintext must be a positive multiple 
    /// of the block (or segment) size.
    pub fn decrypt(&mut self, blocks: &mut [u8]) {
        assert_eq!(blocks.len() % Self::BLOCK_LEN, 0);

        for ciphertext in blocks.chunks_mut(Self::BLOCK_LEN) {
            debug_assert_eq!(ciphertext.len(), Self::BLOCK_LEN);

            let output_block = self.cipher.decrypt(&ciphertext);

            for i in 0..Self::BLOCK_LEN {
                ciphertext[i] = output_block[i];
            }
        }
    }
}

#[test]
fn test_aes128_ecb_enc() {
    // F.1.1  ECB-AES128.Encrypt, (Page-31)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();

    let mut cipher = AesEcb128::new(&key);

    let plaintext = hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710").unwrap();

    let mut ciphertext = plaintext.clone();
    cipher.encrypt(&mut ciphertext);

    assert_eq!(&ciphertext[..], &hex::decode("\
3ad77bb40d7a3660a89ecaf32466ef97\
f5d3d58503b9699de785895a96fdbaaf\
43b1cd7f598ece23881b00e3ed030688\
7b0c785e27e8ad3f8223207104725dd4").unwrap()[..]);
}

#[test]
fn test_aes128_ecb_dec() {
    // F.1.2  ECB-AES128.Decrypt, (Page-31)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key   = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();

    let mut cipher = AesEcb128::new(&key);

    let ciphertext = hex::decode("\
3ad77bb40d7a3660a89ecaf32466ef97\
f5d3d58503b9699de785895a96fdbaaf\
43b1cd7f598ece23881b00e3ed030688\
7b0c785e27e8ad3f8223207104725dd4").unwrap();

    let mut plaintext = ciphertext.clone();
    cipher.decrypt(&mut plaintext);

    assert_eq!(&plaintext[..], &hex::decode("\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710").unwrap()[..]);
}