mod md2;
mod md4;
mod md5;
mod sm3;
mod sha1;
pub mod sha2;


pub use self::md2::*;
pub use self::md4::*;
pub use self::md5::*;
pub use self::sm3::*;
pub use self::sha1::*;


// NOTE: 等待 std::array::FixedSizeArray 稳定后，即可替换。
pub trait Array<T> {
    fn array_as_slice(&self) -> &[T];
    fn array_as_mut_slice(&mut self) -> &mut [T];
}

macro_rules! array_impls {
    ($($N:literal)+) => {
        $(
            impl<T> Array<T> for [T; $N] {
                fn array_as_slice(&self) -> &[T] {
                    self
                }

                fn array_as_mut_slice(&mut self) -> &mut [T] {
                    self
                }

            }
        )+
    }
}
array_impls! {
     0  1  2  3  4  5  6  7  8  9
    10 11 12 13 14 15 16 17 18 19
    20 21 22 23 24 25 26 27 28 29
    30 31 32 33 34 35 36 37 38 39 
    40 41 42 43 44 45 46 47 48 49 
    50 51 52 53 54 55 56 57 58 59 
    60 61 62 63 64
}


// TODO: multihash
// https://github.com/multiformats/multicodec/blob/master/table.csv

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CryptoHashKind {
    MD2,
    MD4,
    MD5,
    SHA1,
    SHA2_256,
    SHA2_384,
    SHA2_512,
}

pub trait CryptoHasher {
    const BLOCK_LEN : usize;
    const OUTPUT_LEN: usize; // Output digest
    
    type Output: Array<u8> + Sized;

    fn finish(&mut self);
    
    fn digest(self) -> Self::Output;

    fn hexdigest(self) -> String 
    where 
        Self: Sized 
    {
        let digest = self.digest();
        let digest: &[u8] = digest.array_as_slice();

        let mut s = String::with_capacity(digest.len()*2);
        for n in digest.iter() {
            s.push_str(format!("{:02x}", n).as_str());
        }
        s
    }

    fn write<T: AsRef<[u8]>>(&mut self, bytes: T);
}

pub trait CryptoHash {
    /// Feeds this value into the given `Hasher`.
    fn crypto_hash<H: CryptoHasher>(&self, state: &mut H);

    /// Feeds a slice of this type into the given `Hasher`.
    fn crypto_hash_slice<H: CryptoHasher>(data: &[Self], state: &mut H)
    where
        Self: Sized,
    {
        for piece in data {
            piece.crypto_hash(state);
        }
    }
}

pub trait BuildCryptoHasher {
    type Hasher: CryptoHasher;

    fn build_hasher() -> Self::Hasher;
}

impl<T: CryptoHash> CryptoHash for [T] {
    fn crypto_hash<H: CryptoHasher>(&self, state: &mut H) {
        CryptoHash::crypto_hash_slice(self, state);
    }
}
impl<'a, T: CryptoHash> CryptoHash for &'a [T] {
    fn crypto_hash<H: CryptoHasher>(&self, state: &mut H) {
        CryptoHash::crypto_hash_slice(self, state);
    }
}



// // =========================== MD5 ===========================
// impl BuildCryptoHasher for crate::md5::Md5 {
//     type Hasher = crate::md5::Md5;

//     fn build_hasher() -> Self::Hasher {
//         crate::md5::Md5::new()
//     }
// }
// impl CryptoHasher for crate::md5::Md5 {
//     const BLOCK_LEN : usize = crate::md5::BLOCK_LEN;
//     const OUTPUT_LEN: usize = crate::md5::DIGEST_LEN; // Output digest
    
//     type Output = [u8; crate::md5::DIGEST_LEN];

//     fn finish(&mut self) {
//         self.finalize();
//     }
    
//     fn digest(self) -> Self::Output {
//         self.output()
//     }

//     fn write<T: AsRef<[u8]>>(&mut self, bytes: T) {
//         self.update(bytes.as_ref());
//     }
// }

// // =========================== SHA1 ===========================
// impl BuildCryptoHasher for crate::sha1::Sha1 {
//     type Hasher = crate::sha1::Sha1;

//     fn build_hasher() -> Self::Hasher {
//         crate::sha1::Sha1::new()
//     }
// }
// impl CryptoHasher for crate::sha1::Sha1 {
//     const BLOCK_LEN : usize = crate::sha1::BLOCK_LEN;
//     const OUTPUT_LEN: usize = crate::sha1::DIGEST_LEN; // Output digest
    
//     type Output = [u8; crate::sha1::DIGEST_LEN];
    
//     fn finish(&mut self) {
//         self.finalize();
//     }
    
//     fn digest(self) -> Self::Output {
//         self.output()
//     }

//     fn write<T: AsRef<[u8]>>(&mut self, bytes: T) {
//         self.update(bytes.as_ref());
//     }
// }


// // =========================== SHA2-256 ===========================
// impl BuildCryptoHasher for crate::sha2::Sha256 {
//     type Hasher = crate::sha2::Sha256;

//     fn build_hasher() -> Self::Hasher {
//         crate::sha2::Sha256::new()
//     }
// }
// impl CryptoHasher for crate::sha2::Sha256 {
//     const BLOCK_LEN : usize = crate::sha2::sha256::BLOCK_LEN;
//     const OUTPUT_LEN: usize = crate::sha2::sha256::DIGEST_LEN; // Output digest
    
//     type Output = [u8; crate::sha2::sha256::DIGEST_LEN];
    
//     fn finish(&mut self) {
//         self.finalize();
//     }
    
//     fn digest(self) -> Self::Output {
//         self.output()
//     }
    
//     fn write<T: AsRef<[u8]>>(&mut self, bytes: T) {
//         self.update(bytes.as_ref());
//     }
// }

// // =========================== SHA2-384 ===========================
// impl BuildCryptoHasher for crate::sha2::Sha384 {
//     type Hasher = crate::sha2::Sha384;

//     fn build_hasher() -> Self::Hasher {
//         crate::sha2::Sha384::new()
//     }
// }
// impl CryptoHasher for crate::sha2::Sha384 {
//     const BLOCK_LEN : usize = crate::sha2::sha512::BLOCK_LEN;
//     const OUTPUT_LEN: usize = crate::sha2::sha512::SHA384_DIGEST_LEN; // Output digest
    
//     type Output = [u8; crate::sha2::sha512::SHA384_DIGEST_LEN];
    
//     fn finish(&mut self) {
//         self.finalize();
//     }
    
//     fn digest(self) -> Self::Output {
//         self.output()
//     }
    
//     fn write<T: AsRef<[u8]>>(&mut self, bytes: T) {
//         self.update(bytes.as_ref());
//     }
// }

// // =========================== SHA2-512 ===========================
// impl BuildCryptoHasher for crate::sha2::Sha512 {
//     type Hasher = crate::sha2::Sha512;

//     fn build_hasher() -> Self::Hasher {
//         crate::sha2::Sha512::new()
//     }
// }
// impl CryptoHasher for crate::sha2::Sha512 {
//     const BLOCK_LEN : usize = crate::sha2::sha512::BLOCK_LEN;
//     const OUTPUT_LEN: usize = crate::sha2::sha512::DIGEST_LEN; // Output digest
    
//     type Output = [u8; crate::sha2::sha512::DIGEST_LEN];
    
//     fn finish(&mut self) {
//         self.finalize();
//     }
    
//     fn digest(self) -> Self::Output {
//         self.output()
//     }
    
//     fn write<T: AsRef<[u8]>>(&mut self, bytes: T) {
//         self.update(bytes.as_ref());
//     }
// }