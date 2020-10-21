// HMAC: Keyed-Hashing for Message Authentication
// https://tools.ietf.org/html/rfc2104
// 
// 参考实现
// https://github.com/python/cpython/blob/3.8/Lib/hmac.py
// https://en.wikipedia.org/wiki/HMAC#Implementation
use crate::hash::{Array, CryptoHasher, BuildCryptoHasher};
use crate::hash::{Md2, Md4, Md5, Sm3, Sha1, Sha256, Sha384, Sha512, };


const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;


pub trait Hmac: BuildCryptoHasher + CryptoHasher {
    fn hmac(key: &[u8], data: &[u8]) -> <<Self as BuildCryptoHasher>::Hasher as CryptoHasher>::Output {
        Self::hmac_inner(key, data, None, None)
    }

    #[doc(hidden)]
    fn hmac_inner(key: &[u8], data1: &[u8], data2: Option<&[u8]>, data3: Option<u8>) -> <<Self as BuildCryptoHasher>::Hasher as CryptoHasher>::Output;
}

macro_rules! impl_hmac {
    ($hasher:path) => {
        impl Hmac for $hasher {
            #[doc(hidden)]
            fn hmac_inner(key: &[u8], data1: &[u8], data2: Option<&[u8]>, data3: Option<u8>) -> <Self as CryptoHasher>::Output {
                if key.len() > <Self as CryptoHasher>::BLOCK_LEN {
                    let mut h = Self::build_hasher();
                    h.write(key);
                    // h.finish();
                    let new_key = h.digest();
                    return Self::hmac_inner(new_key.array_as_slice(), data1, data2, data3);
                }

                let mut ikey = [0u8; <Self as CryptoHasher>::BLOCK_LEN];
                let mut okey = [0u8; <Self as CryptoHasher>::BLOCK_LEN];

                ikey[..key.len()].copy_from_slice(key);
                okey[..key.len()].copy_from_slice(key);
                for idx in 0..<Self as CryptoHasher>::BLOCK_LEN {
                    ikey[idx] ^= IPAD;
                    okey[idx] ^= OPAD;
                }

                // h1 = hash(ipad || message)
                let mut h = Self::build_hasher();
                h.write(&ikey[..]);
                h.write(&data1);
                if let Some(ref data2) = data2 {
                    h.write(data2);
                }
                if let Some(data3) = data3 {
                    h.write(&[data3]);
                }
                // h.finish();
                let h1 = h.digest();

                // h2 = hash(opad || h1)
                let mut h = Self::build_hasher();
                h.write(&okey[..]);
                h.write(&h1[..]);
                // h.finish();
                let h2 = h.digest();

                // return hash(opad || hash(ipad || message)) // Where || is concatenation
                return h2;
            }
        }
    }
}

impl_hmac!(Md2);
impl_hmac!(Md4);
impl_hmac!(Md5);
impl_hmac!(Sm3);
impl_hmac!(Sha1);

// SHA-2
impl_hmac!(Sha256);
impl_hmac!(Sha384);
impl_hmac!(Sha512);

// SHA-3


// TODO: hmac-drbg
// https://github.com/sorpaas/rust-hmac-drbg/blob/master/src/lib.rs


// HMAC_MD5("key", "The quick brown fox jumps over the lazy dog")    = 80070713463e7749b90c2dc24911e275
// HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog")   = de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
// HMAC_SHA256("key", "The quick brown fox jumps over the lazy dog") = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
#[test]
fn test_hmac_md5() {
    // [Page 8] Test Vectors
    // https://tools.ietf.org/html/rfc2104#section-6
    let b16  = [0x0b; 16]; // 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
    let aa16 = [0xaa; 16]; // 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    let dd50 = [0xdd; 50];
    
    let suites: &[(&[u8], &[u8], &str)] = &[
        (b"key", b"The quick brown fox jumps over the lazy dog", "80070713463e7749b90c2dc24911e275"),
        (&b16, b"Hi There", "9294727a3638bb1c13f48ef8158bfc9d"),
        (b"Jefe", b"what do ya want for nothing?", "750c783e6ab0b503eaa86e310a5db738"),
        (&aa16, &dd50, "56be34521d144c88dbb8c733f0e8b3f6"),
    ];
    for (key, data, result) in suites.iter() {
        assert_eq!(&hex::encode(&Md5::hmac(key, data)), result);
    }
}
#[test]
fn test_hmac_sha1() {
    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    let result = "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9";
    
    assert_eq!(&hex::encode(&Sha1::hmac(key, data)), result);
}

#[test]
fn test_hmac_sha2_256() {
    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    let result = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";

    assert_eq!(&hex::encode(&Sha256::hmac(key, data)), result);
}
#[test]
fn test_hmac_sha2_384() {
    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    let result = "d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc592c5d3e1ae50700582a96cf35e1e554995fe4e03381c237";

    assert_eq!(&hex::encode(&Sha384::hmac(key, data)), result);
}
#[test]
fn test_hmac_sha2_512() {
    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    let result = "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a";

    assert_eq!(&hex::encode(&Sha512::hmac(key, data)), result);
}