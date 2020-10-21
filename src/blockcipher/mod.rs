
mod rc2;
mod sm4;
mod aes;
mod aria;
mod camellia;

pub use self::rc2::*;
pub use self::sm4::*;
pub use self::aes::*;
pub use self::aria::*;
pub use self::camellia::*;


#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum BlockCipherKind {
    SM4,
    RC2_FIXED_SIZE,

    AES128,
    AES192,
    AES256,
    
    CAMELLIA128,
    CAMELLIA192,
    CAMELLIA256,

    ARIA128,
    ARIA192,
    ARIA256,
    
    Private(&'static str),
}


// ==============================  对称分组密码  ===============================
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

impl_block_cipher!(Rc2FixedSize, RC2_FIXED_SIZE);
impl_block_cipher!(Sm4, SM4);

impl_block_cipher!(Aes128, AES128);
impl_block_cipher!(Aes192, AES192);
impl_block_cipher!(Aes256, AES256);
impl_block_cipher!(Camellia128, CAMELLIA128);
impl_block_cipher!(Camellia192, CAMELLIA192);
impl_block_cipher!(Camellia256, CAMELLIA256);
impl_block_cipher!(Aria128, ARIA128);
impl_block_cipher!(Aria192, ARIA192);
impl_block_cipher!(Aria256, ARIA256);
