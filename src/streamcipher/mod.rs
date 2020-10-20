use crate::blockmode::{
    Sm4Ctr,
    Aes128Ctr, Aes192Ctr, Aes256Ctr,
    Camellia128Ctr, Camellia192Ctr, Camellia256Ctr,

    Sm4Ofb,
    Aes128Ofb, Aes192Ofb, Aes256Ofb,
    Camellia128Ofb, Camellia192Ofb, Camellia256Ofb,

    Sm4Cfb1,
    Aes128Cfb1, Aes192Cfb1, Aes256Cfb1,
    Camellia128Cfb1, Camellia192Cfb1, Camellia256Cfb1,

    Sm4Cfb8,
    Aes128Cfb8, Aes192Cfb8, Aes256Cfb8,
    Camellia128Cfb8, Camellia192Cfb8, Camellia256Cfb8,

    Sm4Cfb128,
    Aes128Cfb128, Aes192Cfb128, Aes256Cfb128,
    Camellia128Cfb128, Camellia192Cfb128, Camellia256Cfb128,
};


mod rc4;
mod chacha20;

pub use self::rc4::*;
pub use self::chacha20::*;

// TODO: 
//      实现 Salsa20 ？


#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum StreamCipherKind {
    SM4_CTR,
    SM4_OFB,
    SM4_CFB1,
    SM4_CFB8,
    SM4_CFB128,

    AES128_CTR,
    AES192_CTR,
    AES256_CTR,
    
    AES128_OFB,
    AES192_OFB,
    AES256_OFB,
    
    AES128_CFB1,
    AES192_CFB1,
    AES256_CFB1,

    AES128_CFB8,
    AES192_CFB8,
    AES256_CFB8,

    AES128_CFB128,
    AES192_CFB128,
    AES256_CFB128,
    
    CAMELLIA128_CTR,
    CAMELLIA192_CTR,
    CAMELLIA256_CTR,

    CAMELLIA128_OFB,
    CAMELLIA192_OFB,
    CAMELLIA256_OFB,

    CAMELLIA128_CFB1,
    CAMELLIA192_CFB1,
    CAMELLIA256_CFB1,

    CAMELLIA128_CFB8,
    CAMELLIA192_CFB8,
    CAMELLIA256_CFB8,
    
    CAMELLIA128_CFB128,
    CAMELLIA192_CFB128,
    CAMELLIA256_CFB128,

    RC4,
    CHACHA20,
    ZUC,

//     // AEAD
// // 1            AEAD_AES_128_GCM            [RFC5116]
// // 5            AEAD_AES_128_GCM_8          [RFC5282]
// // 7            AEAD_AES_128_GCM_12         [RFC5282]
// // 
// // 2            AEAD_AES_256_GCM            [RFC5116]
// // 6            AEAD_AES_256_GCM_8          [RFC5282]
// // 8            AEAD_AES_256_GCM_12         [RFC5282]
//     AES128_GCM,
//     AES256_GCM,
//     AES128_GCM_8,
//     AES256_GCM_8,
//     AES128_GCM_12,
//     AES256_GCM_12,
// // 3            AEAD_AES_128_CCM            [RFC5116]
// // 9            AEAD_AES_128_CCM_SHORT      [RFC5282]
// // 11           AEAD_AES_128_CCM_SHORT_8    [RFC5282]
// // 13           AEAD_AES_128_CCM_SHORT_12   [RFC5282]
// // 18           AEAD_AES_128_CCM_8          [RFC6655]
// // 
// // 4            AEAD_AES_256_CCM            [RFC5116]
// // 10           AEAD_AES_256_CCM_SHORT      [RFC5282]
// // 12           AEAD_AES_256_CCM_SHORT_8    [RFC5282]
// // 14           AEAD_AES_256_CCM_SHORT_12   [RFC5282]
// // 19           AEAD_AES_256_CCM_8          [RFC6655]
//     AES128_CCM,
//     AES256_CCM,
//     AES128_CCM_8,
//     AES256_CCM_8,
//     AES128_CCM_SHORT,
//     AES256_CCM_SHORT,
//     AES128_CCM_SHORT_8,
//     AES256_CCM_SHORT_8,
//     AES128_CCM_SHORT_12,
//     AES256_CCM_SHORT_12,
// // 15           AEAD_AES_SIV_CMAC_256       [RFC5297]
// // 16           AEAD_AES_SIV_CMAC_384       [RFC5297]
// // 17           AEAD_AES_SIV_CMAC_512       [RFC5297]
//     AES_SIV_CMAC_256,
//     AES_SIV_CMAC_384,
//     AES_SIV_CMAC_512,
// // 30           AEAD_AES_128_GCM_SIV        [RFC8452]
// // 31           AEAD_AES_256_GCM_SIV        [RFC8452]
//     AES_128_GCM_SIV,
//     AES_256_GCM_SIV,
// // | AEAD_AES_128_OCB_TAGLEN128 |   AES-128   |  128   |
// // | AEAD_AES_128_OCB_TAGLEN96  |   AES-128   |   96   |
// // | AEAD_AES_128_OCB_TAGLEN64  |   AES-128   |   64   |
// // | AEAD_AES_192_OCB_TAGLEN128 |   AES-192   |  128   |
// // | AEAD_AES_192_OCB_TAGLEN96  |   AES-192   |   96   |
// // | AEAD_AES_192_OCB_TAGLEN64  |   AES-192   |   64   |
// // | AEAD_AES_256_OCB_TAGLEN128 |   AES-256   |  128   |
// // | AEAD_AES_256_OCB_TAGLEN96  |   AES-256   |   96   |
// // | AEAD_AES_256_OCB_TAGLEN64  |   AES-256   |   64   |
//     AES128_OCB_TAGLEN_64,
//     AES128_OCB_TAGLEN_96,
//     AES128_OCB_TAGLEN_128,
//     AES192_OCB_TAGLEN_64,
//     AES192_OCB_TAGLEN_96,
//     AES192_OCB_TAGLEN_128,
//     AES256_OCB_TAGLEN_64,
//     AES256_OCB_TAGLEN_96,
//     AES256_OCB_TAGLEN_128,

//     CHACHA20_POLY1305,          // AEAD_CHACHA20_POLY1305, IETF AEAD 版本
//     CHACHA20_POLY1305_OPENSSH,  // TODO: 暂未实现
    
    Private(&'static str),
}



// =============================  对称序列密码（流密码）  =============================
// pub trait StreamCipherEncrytor {
//     // 流密码 流式数据加密
//     fn update(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
//     fn finalize(self);
// }

// pub trait StreamCipherDecryptor {
//     // 流密码 流式数据解密
//     fn update(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]);
//     fn finalize(self);
// }

pub trait StreamCipher: Sized {
    const KIND: StreamCipherKind;
    const KEY_LEN: usize;
    const BLOCK_LEN: usize;
    const NONCE_LEN: usize;
    
    // type Encryptor: StreamCipherEncrytor;
    // type Decryptor: StreamCipherDecryptor;

    fn new(key: &[u8], nonce: &[u8]) -> Self;

    fn encrypt_slice_oneshot(key: &[u8], nonce: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]) {
        let mut cipher = Self::new(key, nonce);
        cipher.encrypt_slice(plaintext_in_and_ciphertext_out);
    }

    fn decrypt_slice_oneshot(key: &[u8], nonce: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) {
        let mut cipher = Self::new(key, nonce);
        cipher.decrypt_slice(ciphertext_in_and_plaintext_out);
    }

    fn encrypt_slice(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
    fn decrypt_slice(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]);

    // fn encrypt_stream(&self) -> Self::Encryptor;
    // fn decrypt_stream(&self) -> Self::Encryptor;
}

macro_rules! impl_stream_cipher {
    ($name:tt, $kind:tt) => {
        impl StreamCipher for $name {
            const KIND: StreamCipherKind = StreamCipherKind::$kind;
            const KEY_LEN: usize   = $name::KEY_LEN;
            const BLOCK_LEN: usize = $name::BLOCK_LEN;
            const NONCE_LEN: usize = $name::NONCE_LEN;
            
            fn new(key: &[u8], nonce: &[u8]) -> Self {
                Self::new(key, nonce)
            }

            fn encrypt_slice(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]) {
                self.encrypt(plaintext_in_and_ciphertext_out);
            }

            fn decrypt_slice(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]) {
                self.decrypt(ciphertext_in_and_plaintext_out);
            }
        }
    }
}




// SM4
impl_stream_cipher!(Sm4Ctr, SM4_CTR);
impl_stream_cipher!(Sm4Ofb, SM4_OFB);
impl_stream_cipher!(Sm4Cfb1, SM4_CFB1);
impl_stream_cipher!(Sm4Cfb8, SM4_CFB8);
impl_stream_cipher!(Sm4Cfb128, SM4_CFB128);

// AES
impl_stream_cipher!(Aes128Ctr, AES128_CTR);
impl_stream_cipher!(Aes128Ofb, AES128_OFB);
impl_stream_cipher!(Aes128Cfb1, AES128_CFB1);
impl_stream_cipher!(Aes128Cfb8, AES128_CFB8);
impl_stream_cipher!(Aes128Cfb128, AES128_CFB128);

impl_stream_cipher!(Aes192Ctr, AES192_CTR);
impl_stream_cipher!(Aes192Ofb, AES192_OFB);
impl_stream_cipher!(Aes192Cfb1, AES192_CFB1);
impl_stream_cipher!(Aes192Cfb8, AES192_CFB8);
impl_stream_cipher!(Aes192Cfb128, AES192_CFB128);

impl_stream_cipher!(Aes256Ctr, AES256_CTR);
impl_stream_cipher!(Aes256Ofb, AES256_OFB);
impl_stream_cipher!(Aes256Cfb1, AES256_CFB1);
impl_stream_cipher!(Aes256Cfb8, AES256_CFB8);
impl_stream_cipher!(Aes256Cfb128, AES256_CFB128);

// Camellia
impl_stream_cipher!(Camellia128Ctr, CAMELLIA128_CTR);
impl_stream_cipher!(Camellia128Ofb, CAMELLIA128_OFB);
impl_stream_cipher!(Camellia128Cfb1, CAMELLIA128_CFB1);
impl_stream_cipher!(Camellia128Cfb8, CAMELLIA128_CFB8);
impl_stream_cipher!(Camellia128Cfb128, CAMELLIA128_CFB128);

impl_stream_cipher!(Camellia192Ctr, CAMELLIA192_CTR);
impl_stream_cipher!(Camellia192Ofb, CAMELLIA192_OFB);
impl_stream_cipher!(Camellia192Cfb1, CAMELLIA192_CFB1);
impl_stream_cipher!(Camellia192Cfb8, CAMELLIA192_CFB8);
impl_stream_cipher!(Camellia192Cfb128, CAMELLIA192_CFB128);

impl_stream_cipher!(Camellia256Ctr, CAMELLIA256_CTR);
impl_stream_cipher!(Camellia256Ofb, CAMELLIA256_OFB);
impl_stream_cipher!(Camellia256Cfb1, CAMELLIA256_CFB1);
impl_stream_cipher!(Camellia256Cfb8, CAMELLIA256_CFB8);
impl_stream_cipher!(Camellia256Cfb128, CAMELLIA256_CFB128);

// Chacha20
impl_stream_cipher!(Chacha20, CHACHA20);
