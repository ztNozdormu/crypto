use std::io;


#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum BlockCipherKind {
    AES128,
    AES192,
    AES256,
    AES128_ECB,
    AES128_CBC,
    AES128_CFB64,
    AES128_CFB128,
    // Aria
    CAMELLIA128,
    CAMELLIA192,
    CAMELLIA256,

    RC2,
    SM4,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum StreamCipherKind {
    AES128_CFB1,
    AES128_CFB8,
    AES128_OFB,
    AES128_CTR,
    
    AES128_GCM,
    AES128_CCM,
    // TODO: 添加更多 ...

    RC4,
    CHACHA20,
    ZUC,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AuthenticatedStreamCipherKind {
    AES128_GCM,
    AES128_CCM,
    // TODO: 添加更多 ...
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AeadStreamCipherKind {
    AEAD_AES_128_GCM,
    AEAD_AES_256_GCM,
    AEAD_AES_128_CCM,
    // TODO: 添加更多 ...
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

    fn encrypt_block(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
    fn decrypt_block(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]);
}


// =============================  流密码  =============================
pub trait StreamCipherEncrytor {
    // 流密码 流式数据加密
    fn update(&mut self, plaintext: &[u8], ciphertext: &mut [u8]);
    fn finalize(self);
}
pub trait StreamCipherDecryptor {
    // 流密码 流式数据解密
    fn update(&mut self, ciphertext: &[u8], plaintext: &mut [u8]);
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

    fn encrypt_slice(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
    fn decrypt_slice(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]);

    fn encrypt_stream(&self) -> Self::Encryptor;
    fn decrypt_stream(&self) -> Self::Encryptor;
}


// =================== 认证加密（Authenticated encryption, AE）=======================
pub trait AuthenticatedStreamCipherEncrytor {
    fn update(&mut self, plaintext: &[u8], ciphertext: &mut [u8]);
    // NOTE: 追加 TAG 数据至 output 的结尾。
    fn finalize(self, tag: &mut [u8]);
}
pub trait AuthenticatedStreamCipherDecryptor {
    fn update(&mut self, ciphertext: &[u8], plaintext: &mut [u8]);
    // NOTE: 验证 TAG 数据是否吻合。
    fn finalize(self, tag: &[u8]) -> Result<(), ()>;
}
pub trait AuthenticatedStreamCipher: StreamCipher {
    const KIND: AuthenticatedStreamCipherKind;
    const TAG_LEN: usize;

    type AeEncryptor: AuthenticatedStreamCipherEncrytor;
    type AeDecryptor: AuthenticatedStreamCipherDecryptor;

    fn ae_encrypt_slice_oneshot(key: &[u8], nonce: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]) {
        let mut cipher = Self::new(key, nonce);
        cipher.ae_encrypt_slice(plaintext_in_and_ciphertext_out);
    }

    fn ae_decrypt_slice_oneshot(key: &[u8], nonce: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) {
        let mut cipher = Self::new(key, nonce);
        cipher.ae_decrypt_slice(ciphertext_in_and_plaintext_out);
    }

    fn ae_encrypt_slice(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
    fn ae_decrypt_slice(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]);

    fn ae_encrypt_stream(&self) -> Self::AeEncryptor;
    fn ae_decrypt_stream(&self) -> Self::AeDecryptor;
}


// =================== 带有关联数据的认证加密（authenticated encryption with associated data, AEAD）==============
pub trait AeadStreamCipherEncrytor {
    fn update(&mut self, plaintext: &[u8], ciphertext: &mut [u8]);
    // NOTE: 追加 TAG 数据至 output 的结尾。
    fn finalize(self, tag: &mut [u8]);
}
pub trait AeadStreamCipherDecryptor {
    fn update(&mut self, ciphertext: &[u8], plaintext: &mut [u8]);
    // NOTE: 验证 TAG 数据是否吻合。
    fn finalize(self, tag: &[u8]) -> Result<(), ()>;
}
pub trait AeadStreamCipher: AuthenticatedStreamCipher {
    const KIND: AeadStreamCipherKind;
    const ID: u16;                 // IANA AEAD ID
    const NAME: &'static str;      // IANA AEAD Name
    const REFERENCE: &'static str; // IANA AEAD Reference

    type AeadEncryptor: AeadStreamCipherEncrytor;
    type AeadDecryptor: AeadStreamCipherDecryptor;

    fn aead_encrypt_slice_oneshot(key: &[u8], nonce: &[u8], aad: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]) {
        let mut cipher = Self::new(key, nonce);
        cipher.aead_encrypt_slice(aad, plaintext_in_and_ciphertext_out);
    }

    fn aead_decrypt_slice_oneshot(key: &[u8], nonce: &[u8], aad: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) {
        let mut cipher = Self::new(key, nonce);
        cipher.aead_decrypt_slice(aad, ciphertext_in_and_plaintext_out);
    }

    fn aead_encrypt_slice(&mut self, aad: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]);
    fn aead_decrypt_slice(&mut self, aad: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]);

    fn aead_encrypt_stream(&self) -> Self::AeadEncryptor;
    fn aead_decrypt_stream(&self) -> Self::AeadDecryptor;
}

