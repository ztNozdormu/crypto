
// HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
// https://tools.ietf.org/html/rfc5869
// 
// 参考实现
// https://github.com/casebeer/python-hkdf/blob/master/hkdf.py
// https://en.wikipedia.org/wiki/HKDF#Example:_Python_implementation

use crate::hmac::Hmac;
use crate::hash::{Array, CryptoHasher, BuildCryptoHasher};
use crate::hash::{Md2, Md4, Md5, Sm3, Sha1, Sha256, Sha384, Sha512, };


pub trait Hkdf: Hmac {
    // Inputs:
    //      salt     optional salt value (a non-secret random value);
    //               if not provided, it is set to a string of HashLen zeros.
    //      IKM      input keying material
    // 
    // Output:
    //      PRK      a pseudorandom key (of HashLen octets)
    fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> <<Self as BuildCryptoHasher>::Hasher as CryptoHasher>::Output;

    // Inputs:
    //      PRK      a pseudorandom key of at least HashLen octets
    //               (usually, the output from the extract step)
    //      info     optional context and application specific information
    //               (can be a zero-length string)
    //      L        length of output keying material in octets
    //               (<= 255*HashLen)
    // Output:
    //      OKM      output keying material (of L octets)
    fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8>;
}

macro_rules! impl_hkdf {
    ($hasher:ident) => {
        impl Hkdf for $hasher {
            fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> <<Self as BuildCryptoHasher>::Hasher as CryptoHasher>::Output {
                // PRK = HMAC-Hash(salt, IKM)
                if salt.is_empty() {
                    let salt = [0u8; <<Self as BuildCryptoHasher>::Hasher as CryptoHasher>::OUTPUT_LEN];
                    $hasher::hmac(&salt[..], ikm)
                } else {
                    $hasher::hmac(salt, ikm)
                }
            }
            
            fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
                assert!(len <= <<Self as BuildCryptoHasher>::Hasher as CryptoHasher>::OUTPUT_LEN * 255);
                // N = ceil(L/HashLen)
                // T = T(1) | T(2) | T(3) | ... | T(N)
                // OKM = first L octets of T
                // 
                // where:
                // T(0) = empty string (zero length)
                // T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
                // T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
                // T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
                // ...
                // 
                // (where the constant concatenated to the end of each T(n) is a
                // single octet.)
                let mut n = len / <<Self as BuildCryptoHasher>::Hasher as CryptoHasher>::OUTPUT_LEN;
                if len % <<Self as BuildCryptoHasher>::Hasher as CryptoHasher>::OUTPUT_LEN != 0 {
                    // ceil
                    n += 1;
                }
                assert!(n <= std::u8::MAX as usize);

                let mut t = [0u8; <<Self as BuildCryptoHasher>::Hasher as CryptoHasher>::OUTPUT_LEN];
                let mut okm: Vec<u8> = Vec::with_capacity(n * <<Self as BuildCryptoHasher>::Hasher as CryptoHasher>::OUTPUT_LEN);

                let n = n as u8;
                for i in 0..n {
                    if i == 0 {
                        t = $hasher::hmac_inner(prk, &[], Some(info), Some(i + 1));
                    } else {
                        t = $hasher::hmac_inner(prk, &t[..], Some(info), Some(i + 1));
                    }
                    okm.extend_from_slice(&t.array_as_slice());
                }

                okm.truncate(len);

                okm
            }
        }
    }
}

impl_hkdf!(Md2);
impl_hkdf!(Md4);
impl_hkdf!(Md5);
impl_hkdf!(Sm3);
impl_hkdf!(Sha1);

// SHA-2
impl_hkdf!(Sha256);
impl_hkdf!(Sha384);
impl_hkdf!(Sha512);

// SHA-3



#[cfg(test)]
fn hexdecode(s: &str) -> Vec<u8> {
    let h = s.replace("0x", "").replace(" ", "").replace("\n", "").replace("\r", "");
    hex::decode(&h).unwrap()
}

#[test]
fn test_hkdf() {
    // Appendix A.  Test Vectors
    // https://tools.ietf.org/html/rfc5869#appendix-A

    // Test Case 1
    let ikm = hexdecode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hexdecode("000102030405060708090a0b0c");
    let info = hexdecode("f0f1f2f3f4f5f6f7f8f9");
    let len = 42usize;

    assert_eq!(ikm.len(), 22);
    assert_eq!(salt.len(), 13);
    assert_eq!(info.len(), 10);

    let prk = Sha256::hkdf_extract(&salt, &ikm);
    assert_eq!(prk.len(), 32);
    assert_eq!(&hex::encode(&prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

    let okm = Sha256::hkdf_expand(&prk, &info, len);
    assert_eq!(okm.len(), len);
    assert_eq!(&hex::encode(&okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    // Test Case 2
    let ikm = hexdecode("0x000102030405060708090a0b0c0d0e0f\
101112131415161718191a1b1c1d1e1f\
202122232425262728292a2b2c2d2e2f\
303132333435363738393a3b3c3d3e3f\
404142434445464748494a4b4c4d4e4f\
");
    let salt = hexdecode("0x606162636465666768696a6b6c6d6e6f\
707172737475767778797a7b7c7d7e7f\
808182838485868788898a8b8c8d8e8f\
909192939495969798999a9b9c9d9e9f\
a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
");
    let info = hexdecode("0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\
");
    let len = 82usize;

    let prk = Sha256::hkdf_extract(&salt, &ikm);
    assert_eq!(prk.len(), 32);
    assert_eq!(&hex::encode(&prk), "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");

    let okm = Sha256::hkdf_expand(&prk, &info, len);
    assert_eq!(okm.len(), len);
    assert_eq!(&hex::encode(&okm), "b11e398dc80327a1c8e7f78c596a4934\
4f012eda2d4efad8a050cc4c19afa97c\
59045a99cac7827271cb41c65e590e09\
da3275600c2f09b8367793a9aca3db71\
cc30c58179ec3e87c14c01d5c1f3434f\
1d87\
");

    // Test Case 3
    let ikm = hexdecode("0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = [];
    let info = [];
    let len = 42usize;

    let prk = Sha256::hkdf_extract(&salt, &ikm);
    assert_eq!(prk.len(), 32);
    assert_eq!(&hex::encode(&prk), "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");

    let okm = Sha256::hkdf_expand(&prk, &info, len);
    assert_eq!(okm.len(), len);
    assert_eq!(&hex::encode(&okm), "8da4e775a563c18f715f802a063c5a31\
b8a11f5c5ee1879ec3454e5f3c738d2d\
9d201395faa4b61a96c8\
");

    // Test Case 4
    let ikm = hexdecode("0x0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hexdecode("0x000102030405060708090a0b0c");
    let info = hexdecode("0xf0f1f2f3f4f5f6f7f8f9");
    let len = 42usize;

    let prk = Sha1::hkdf_extract(&salt, &ikm);
    assert_eq!(&hex::encode(&prk), "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243");

    let okm = Sha1::hkdf_expand(&prk, &info, len);
    assert_eq!(okm.len(), len);
    assert_eq!(&hex::encode(&okm), "085a01ea1b10f36933068b56efa5ad81\
a4f14b822f5b091568a9cdd4f155fda2\
c22e422478d305f3f896\
");

    // Test Case 5
    let ikm = hexdecode("0x000102030405060708090a0b0c0d0e0f\
101112131415161718191a1b1c1d1e1f\
202122232425262728292a2b2c2d2e2f\
303132333435363738393a3b3c3d3e3f\
404142434445464748494a4b4c4d4e4f\
");
    let salt = hexdecode("0x606162636465666768696a6b6c6d6e6f\
707172737475767778797a7b7c7d7e7f\
808182838485868788898a8b8c8d8e8f\
909192939495969798999a9b9c9d9e9f\
a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
");
    let info = hexdecode("0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\
");
    let len = 82usize;

    let prk = Sha1::hkdf_extract(&salt, &ikm);
    assert_eq!(&hex::encode(&prk), "8adae09a2a307059478d309b26c4115a224cfaf6");

    let okm = Sha1::hkdf_expand(&prk, &info, len);
    assert_eq!(okm.len(), len);
    assert_eq!(&hex::encode(&okm), "0bd770a74d1160f7c9f12cd5912a06eb\
ff6adcae899d92191fe4305673ba2ffe\
8fa3f1a4e5ad79f3f334b3b202b2173c\
486ea37ce3d397ed034c7f9dfeb15c5e\
927336d0441f4c4300e2cff0d0900b52\
d3b4\
");

    // Test Case 6
    let ikm = hexdecode("0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = [];
    let info = [];
    let len = 42usize;

    let prk = Sha1::hkdf_extract(&salt, &ikm);
    assert_eq!(&hex::encode(&prk), "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01");

    let okm = Sha1::hkdf_expand(&prk, &info, len);
    assert_eq!(okm.len(), len);
    assert_eq!(&hex::encode(&okm), "0ac1af7002b3d761d1e55298da9d0506\
b9ae52057220a306e07b6b87e8df21d0\
ea00033de03984d34918\
");

    // Test Case 7
    let ikm = hexdecode("0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
    // NOTE: not provided (defaults to HashLen zero octets)
    let salt = [];
    let info = [];
    let len = 42usize;

    let prk = Sha1::hkdf_extract(&salt, &ikm);
    assert_eq!(&hex::encode(&prk), "2adccada18779e7c2077ad2eb19d3f3e731385dd");

    let okm = Sha1::hkdf_expand(&prk, &info, len);
    assert_eq!(okm.len(), len);
    assert_eq!(&hex::encode(&okm), "2c91117204d745f3500d636a62f64f0a\
b3bae548aa53d423b0d1f27ebba6f5e5\
673a081d70cce7acfc48\
");
}

