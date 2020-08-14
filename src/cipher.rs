
use crate::error::AuthenticationTagMismatch;
use crate::aes::Aes128;
use crate::aes::Aes192;
use crate::aes::Aes256;

use std::io;


#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CipherKind {
    AES128,
    AES192,
    AES256,
    AES128_ECB,
    AES128_CBC,
    AES128_CFB64,
    AES128_CFB128,
    CAMELLIA128,
    // TODO: 添加更多 ...
    Private {
        id: u16,
        name: &'static str,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum BlockCipherKind {
    AES128,
    AES192,
    AES256,
    AES128_ECB,
    AES192_ECB,
    AES256_ECB,
    AES128_CBC,
    AES192_CBC,
    AES256_CBC,
    AES128_CFB64,
    AES192_CFB64,
    AES256_CFB64,
    AES128_CFB128,
    AES192_CFB128,
    AES256_CFB128,
    CAMELLIA128,
    CAMELLIA192,
    CAMELLIA256,
    CAMELLIA128_ECB,
    CAMELLIA192_ECB,
    CAMELLIA256_ECB,
    CAMELLIA128_CBC,
    CAMELLIA192_CBC,
    CAMELLIA256_CBC,
    CAMELLIA128_CFB64,
    CAMELLIA192_CFB64,
    CAMELLIA256_CFB64,
    CAMELLIA128_CFB128,
    CAMELLIA192_CFB128,
    CAMELLIA256_CFB128,
    
    // TODO: 添加更多 ...
    RC2,
    SM4,

    Private {
        id: u16,
        name: &'static str,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum StreamCipherKind {
    AES128_CFB1,
    AES192_CFB1,
    AES256_CFB1,
    AES128_CFB8,
    AES192_CFB8,
    AES256_CFB8,
    AES128_OFB,
    AES192_OFB,
    AES256_OFB,
    AES128_CTR,
    AES192_CTR,
    AES256_CTR,
    
    AES128_GCM,
    AES128_CCM,

    AES128_SIV_CMAC256,
    AES128_SIV_CMAC384,
    AES128_SIV_CMAC512,

    AES128_GCM_SIV,

    // TODO: 添加更多 ...

    RC4,
    CHACHA20,
    ZUC,

    Private {
        id: u16,
        name: &'static str,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AuthenticatedStreamCipherKind {
    AES128_GCM,
    AES128_CCM,
    // TODO: 添加更多 ...

    Private {
        id: u16,
        name: &'static str,
    },
}

// Authenticated Encryption with Associated Data (AEAD) Parameters
// https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AeadStreamCipherKind {
    AEAD_AES_128_GCM,
    AEAD_AES_256_GCM,
    AEAD_AES_128_CCM,
    AEAD_AES_256_CCM,
    AEAD_AES_128_GCM_8,
    AEAD_AES_256_GCM_8,
    AEAD_AES_128_GCM_12,
    AEAD_AES_256_GCM_12,
    AEAD_AES_128_CCM_SHORT,
    AEAD_AES_256_CCM_SHORT,
    AEAD_AES_128_CCM_SHORT_8,
    AEAD_AES_256_CCM_SHORT_8,
    AEAD_AES_128_CCM_SHORT_12,
    AEAD_AES_256_CCM_SHORT_12,
    AEAD_AES_SIV_CMAC_256,
    AEAD_AES_SIV_CMAC_384,
    AEAD_AES_SIV_CMAC_512,
    AEAD_AES_128_CCM_8,
    AEAD_AES_256_CCM_8,
    AEAD_AES_128_OCB_TAGLEN128,
    AEAD_AES_128_OCB_TAGLEN96,
    AEAD_AES_128_OCB_TAGLEN64,
    AEAD_AES_192_OCB_TAGLEN128,
    AEAD_AES_192_OCB_TAGLEN96,
    AEAD_AES_192_OCB_TAGLEN64,
    AEAD_AES_256_OCB_TAGLEN128,
    AEAD_AES_256_OCB_TAGLEN96,
    AEAD_AES_256_OCB_TAGLEN64,
    AEAD_CHACHA20_POLY1305,
    AEAD_AES_128_GCM_SIV,
    AEAD_AES_256_GCM_SIV,

    Private {
        id: u16,
        name: &'static str,
    },
}



// ==============================  分组密码  ===============================
pub trait BlockCipher: Sized {
    const KIND: BlockCipherKind;
    const KEY_LEN: usize;
    const BLOCK_LEN: usize;
    
    fn new(key: &[u8]) -> Self;
    
    fn encrypt_block_oneshot(key: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]) {
        let mut cipher = Self::new(key);
        cipher.encrypt_block(plaintext_in_and_ciphertext_out);
    }

    fn decrypt_block_oneshot(key: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) {
        let mut cipher = Self::new(key);
        cipher.decrypt_block(ciphertext_in_and_plaintext_out);
    }

    fn kind(&self) -> BlockCipherKind {
        Self::KIND
    }

    fn key_len(&self) -> usize {
        Self::KEY_LEN
    }

    fn block_len(&self) -> usize {
        Self::BLOCK_LEN
    }

    fn encrypt_block(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
    fn decrypt_block(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]);
}


// =============================  流密码  =============================
pub trait StreamCipherEncrytor {
    // 流密码 流式数据加密
    fn update(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
    fn finalize(self);
}
pub trait StreamCipherDecryptor {
    // 流密码 流式数据解密
    fn update(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]);
    fn finalize(self);
}
pub trait StreamCipher: Sized {
    const KIND: StreamCipherKind;
    const KEY_LEN: usize;
    const BLOCK_LEN: usize;
    const NONCE_LEN: usize;
    
    type Encryptor: StreamCipherEncrytor;
    type Decryptor: StreamCipherDecryptor;

    fn new(key: &[u8], nonce: &[u8]) -> Self;

    fn encrypt_slice_oneshot(key: &[u8], nonce: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]) {
        let mut cipher = Self::new(key, nonce);
        cipher.encrypt_slice(plaintext_in_and_ciphertext_out);
    }

    fn decrypt_slice_oneshot(key: &[u8], nonce: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) {
        let mut cipher = Self::new(key, nonce);
        cipher.decrypt_slice(ciphertext_in_and_plaintext_out);
    }

    fn kind(&self) -> StreamCipherKind {
        Self::KIND
    }

    fn key_len(&self) -> usize {
        Self::KEY_LEN
    }
    
    fn block_len(&self) -> usize {
        Self::BLOCK_LEN
    }

    fn nonce_len(&self) -> usize {
        Self::NONCE_LEN
    }

    fn encrypt_slice(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
    fn decrypt_slice(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]);

    fn encrypt_stream(&self) -> Self::Encryptor;
    fn decrypt_stream(&self) -> Self::Encryptor;
}


// =================== 认证加密（Authenticated encryption, AE）=======================
pub trait AuthenticatedStreamCipherEncrytor {
    fn update(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
    // NOTE: 追加 TAG 数据至 output 的结尾。
    fn finalize(self, tag: &mut [u8]);
}
pub trait AuthenticatedStreamCipherDecryptor {
    fn update(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]);
    // NOTE: 验证 TAG 数据是否吻合。
    fn finalize(self, tag: &[u8]) -> Result<(), AuthenticationTagMismatch>;
}
pub trait AuthenticatedStreamCipher: StreamCipher {
    const AE_KIND: AuthenticatedStreamCipherKind;
    const TAG_LEN: usize;

    type AeEncryptor: AuthenticatedStreamCipherEncrytor;
    type AeDecryptor: AuthenticatedStreamCipherDecryptor;

    fn ae_encrypt_slice_oneshot(key: &[u8], nonce: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]) {
        let mut cipher = Self::new(key, nonce);
        cipher.ae_encrypt_slice(plaintext_in_and_ciphertext_out);
    }

    fn ae_decrypt_slice_oneshot(key: &[u8], nonce: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) -> Result<(), AuthenticationTagMismatch> {
        let mut cipher = Self::new(key, nonce);
        cipher.ae_decrypt_slice(ciphertext_in_and_plaintext_out)
    }

    fn ae_kind(&self) -> AuthenticatedStreamCipherKind {
        Self::AE_KIND
    }

    fn ae_tag_len(&self) -> usize {
        Self::TAG_LEN
    }

    fn ae_encrypt_slice(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
    fn ae_decrypt_slice(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]) -> Result<(), AuthenticationTagMismatch>;

    fn ae_encrypt_stream(&self) -> Self::AeEncryptor;
    fn ae_decrypt_stream(&self) -> Self::AeDecryptor;
}


// =================== 带有关联数据的认证加密（authenticated encryption with associated data, AEAD）==============
pub trait AeadStreamCipherEncrytor {
    fn update(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
    // NOTE: 追加 TAG 数据至 output 的结尾。
    fn finalize(self, tag: &mut [u8]);
}
pub trait AeadStreamCipherDecryptor {
    fn update(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]);
    // NOTE: 验证 TAG 数据是否吻合。
    fn finalize(self, tag: &[u8]) -> Result<(), AuthenticationTagMismatch>;
}
pub trait AeadStreamCipher: AuthenticatedStreamCipher {
    const AEAD_KIND: AeadStreamCipherKind;
    const ID: u16;                 // IANA AEAD ID
    const NAME: &'static str;      // IANA AEAD Name
    const REFERENCE: &'static str; // IANA AEAD Reference

    type AeadEncryptor: AeadStreamCipherEncrytor;
    type AeadDecryptor: AeadStreamCipherDecryptor;

    fn aead_encrypt_slice_oneshot(key: &[u8], nonce: &[u8], aad: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]) {
        let mut cipher = Self::new(key, nonce);
        cipher.aead_encrypt_slice(aad, plaintext_in_and_ciphertext_out);
    }

    fn aead_decrypt_slice_oneshot(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) -> Result<(), AuthenticationTagMismatch> {
        let mut cipher = Self::new(key, nonce);
        cipher.aead_decrypt_slice(aad, ciphertext_in_and_plaintext_out)
    }

    fn ae_kind(&self) -> AeadStreamCipherKind {
        Self::AEAD_KIND
    }

    fn aead_encrypt_slice(&mut self, aad: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]);
    fn aead_decrypt_slice(&mut self, aad: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) -> Result<(), AuthenticationTagMismatch>;

    fn aead_encrypt_stream(&self) -> Self::AeadEncryptor;
    fn aead_decrypt_stream(&self) -> Self::AeadDecryptor;
}



macro_rules! impl_block_cipher {
    ($name:tt, $kind:tt) => {
        impl BlockCipher for $name {
            const KIND: BlockCipherKind = BlockCipherKind::$kind;
            const KEY_LEN: usize   = $name::KEY_LEN;
            const BLOCK_LEN: usize = $name::BLOCK_LEN;

            fn new(key: &[u8]) -> Self {
                Self::new(key)
            }

            fn encrypt_block(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]) {
                self.encrypt(plaintext_in_and_ciphertext_out);
            }

            fn decrypt_block(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]) {
                self.decrypt(ciphertext_in_and_plaintext_out);
            }
        }
    }
}
impl_block_cipher!(Aes128, AES128);
impl_block_cipher!(Aes192, AES192);
impl_block_cipher!(Aes256, AES256);


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

pub fn ae_encrypt_slice<C: AuthenticatedStreamCipher>(key: &[u8], 
                                                      nonce: &[u8], 
                                                      plaintext_in_and_ciphertext_out: &mut [u8]) {
    C::ae_encrypt_slice_oneshot(key, nonce, plaintext_in_and_ciphertext_out)
}
pub fn ae_decrypt_slice<C: AuthenticatedStreamCipher>(key: &[u8], 
                                                      nonce: &[u8], 
                                                      ciphertext_in_and_plaintext_out: &mut [u8]
) -> Result<(), AuthenticationTagMismatch> {
    C::ae_decrypt_slice_oneshot(key, nonce, ciphertext_in_and_plaintext_out)
}

pub fn aead_encrypt_slice<C: AeadStreamCipher>(key: &[u8], 
                                               nonce: &[u8], 
                                               aad: &[u8], 
                                               plaintext_in_and_ciphertext_out: &mut [u8]) {
    C::aead_encrypt_slice_oneshot(key, nonce, aad, plaintext_in_and_ciphertext_out)
}
pub fn aead_decrypt_slice<C: AeadStreamCipher>(key: &[u8],
                                              nonce: &[u8], 
                                              aad: &[u8], 
                                              ciphertext_in_and_plaintext_out: &mut [u8]
) -> Result<(), AuthenticationTagMismatch> {
    C::aead_decrypt_slice_oneshot(key, nonce, aad, ciphertext_in_and_plaintext_out)
}


// impl AeadStreamCipher for AeadAes128Gcm {
//     const ID: u16                 = 1;
//     const NAME: &'static str      = "AEAD_AES_128_GCM";
//     const REFERENCE: &'static str = "RFC5116";
// }