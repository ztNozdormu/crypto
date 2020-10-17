use subtle;
use crate::aes::Aes128;

mod ghash;

pub use self::ghash::GHash;


// Recommendation for Block Cipher Modes of Operation:  Galois/Counter Mode (GCM) and GMAC
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// 
// Galois/Counter Mode:
// https://en.wikipedia.org/wiki/Galois/Counter_Mode
// 
// NOTE: 
//      1. GCM 认证算法本身支持变长的 IV，但是目前普遍的实现都是限制 IV 长度至 12 Bytes。
//      2. GCM 只可以和 块大小为 16 Bytes 的块密码算法协同工作。
//      3. GCM 不接受用户输入的 BlockCounter。
// 
// IANA AEAD:
// 
// AEAD_AES_128_GCM_8   // TAG_LEN:  8
// AEAD_AES_128_GCM_12  // TAG_LEN: 12
// AEAD_AES_128_GCM     // TAG LEN: 16
// 
// AEAD_AES_256_GCM_8   // TAG_LEN:  8
// AEAD_AES_256_GCM_12  // TAG_LEN: 12
// AEAD_AES_256_GCM     // TAG LEN: 16


const GCM_BLOCK_LEN: usize = 16;

#[derive(Debug, Clone)]
pub struct Aes128Gcm {
    cipher: Aes128,
    ghash: GHash,
    nonce: [u8; Self::NONCE_LEN],
}

// 6.  AES GCM Algorithms for Secure Shell
// https://tools.ietf.org/html/rfc5647#section-6
impl Aes128Gcm {
    pub const BLOCK_LEN: usize = Aes128::BLOCK_LEN;
    pub const TAG_LEN: usize   = 16;
    // NOTE: GCM 认证算法本身支持变长的 IV，但是目前普遍的实现都是限制 IV 长度至 12 Bytes。
    //       这样和 BlockCounter (u32) 合在一起 组成一个 Nonce，为 12 + 4 = 16 Bytes。
    pub const IV_LEN: usize    = 12;
    pub const NONCE_LEN: usize = Self::IV_LEN + 4; // 16 Bytes

    pub const A_MAX: usize = 2305843009213693952; // 2 ** 61

    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        // NOTE: GCM 只可以和 块大小为 16 Bytes 的块密码算法协同工作。
        assert_eq!(Self::BLOCK_LEN, GCM_BLOCK_LEN);
        assert_eq!(Self::BLOCK_LEN, GHash::BLOCK_LEN);
        assert_eq!(key.len(), Aes128::KEY_LEN);
        // NOTE: 前面 12 Bytes 为 IV，后面 4 Bytes 为 BlockCounter。
        //       BlockCounter 不接受用户的输入，如果输入了直接忽略。
        assert!(iv.len() >= Self::IV_LEN);

        let mut nonce = [0u8; Self::NONCE_LEN];
        nonce[..Self::IV_LEN].copy_from_slice(&iv[..Self::IV_LEN]);
        nonce[15] = 1; // 初始化计数器

        let cipher = Aes128::new(key);

        // NOTE: 计算 Ghash 初始状态。
        let mut h = [0u8; Self::BLOCK_LEN];
        cipher.encrypt(&mut h);

        let ghash = GHash::new(&h);

        Self { cipher, ghash, nonce }
    }

    #[inline]
    pub fn ae_encrypt(&mut self, plaintext_and_ciphertext: &mut [u8]) {
        self.aead_encrypt(&[], plaintext_and_ciphertext);
    }
    
    #[inline]
    pub fn ae_decrypt(&mut self, ciphertext_and_plaintext: &mut [u8]) -> bool {
        self.aead_decrypt(&[], ciphertext_and_plaintext)
    }

    #[inline]
    fn block_num_inc(nonce: &mut [u8; Self::BLOCK_LEN]) {
        // Counter inc
        for i in 1..5 {
            nonce[16 - i] = nonce[16 - i].wrapping_add(1);
            if nonce[16 - i] != 0 {
                break;
            }
        }
    }

    #[inline]
    fn hash_aad(&self, aad: &[u8], buf: &mut [u8; Self::BLOCK_LEN] ) {
        if aad.is_empty() {
            return ();
        }

        for chunk in aad.chunks(Self::BLOCK_LEN) {
            for i in 0..chunk.len() {
                buf[i] ^= chunk[i];
            }
            self.ghash.ghash(buf);
        }
    }

    pub fn aead_encrypt(&mut self, aad: &[u8], plaintext_and_ciphertext: &mut [u8]) {
        debug_assert!(aad.len() < Self::A_MAX);
        // debug_assert!(plaintext_and_ciphertext.len() < Self::C_MAX);
        debug_assert!(plaintext_and_ciphertext.len() >= Self::TAG_LEN);

        let alen = aad.len();
        let plen = plaintext_and_ciphertext.len() - Self::TAG_LEN;
        let plaintext = &mut plaintext_and_ciphertext[..plen];

        let mut counter_block = self.nonce.clone();
        // NOTE: 初始化 BlockCounter 计数器
        counter_block[12] = 0;
        counter_block[13] = 0;
        counter_block[14] = 0;
        counter_block[15] = 1;

        let mut base_ectr = counter_block.clone();
        self.cipher.encrypt(&mut base_ectr);

        let mut buf = [0u8; 16];

        self.hash_aad(aad, &mut buf);

        //////// Update ////////
        for (block_index, chunk) in plaintext.chunks_mut(Self::BLOCK_LEN).enumerate() {
            Self::block_num_inc(&mut counter_block);

            let mut ectr = counter_block.clone();
            self.cipher.encrypt(&mut ectr);

            for i in 0..chunk.len() {
                chunk[i] = ectr[i] ^ chunk[i];
                buf[i] ^= chunk[i];
            }

            self.ghash.ghash(&mut buf);
        }

        // Finalize
        let plen_bits: u64 = (plen as u64) * 8;
        let alen_bits: u64 = (alen as u64) * 8;
        
        let mut octets = [0u8; 16];
        let mut tag = [0u8; Self::TAG_LEN];
        tag[..Self::TAG_LEN].copy_from_slice(&base_ectr[..Self::TAG_LEN]);

        octets[0.. 8].copy_from_slice(&alen_bits.to_be_bytes());
        octets[8..16].copy_from_slice(&plen_bits.to_be_bytes());

        for i in 0..Self::BLOCK_LEN {
            buf[i] ^= octets[i];
        }

        self.ghash.ghash(&mut buf);

        for i in 0..Self::TAG_LEN {
            tag[i] ^= buf[i];
        }

        let tag_out = &mut plaintext_and_ciphertext[plen..plen + Self::TAG_LEN];
        // Append Tag.
        tag_out.copy_from_slice(&tag);
    }

    // pub fn decrypt(&mut self, ciphertext: &[u8], input_tag: &[u8; Self::TAG_LEN], plaintext: &mut [u8]) -> bool {
    pub fn aead_decrypt(&mut self, aad: &[u8], ciphertext_and_plaintext: &mut [u8]) -> bool {
        // debug_assert_eq!(plaintext.len(), ciphertext.len());
        // debug_assert_eq!(input_tag.len(), Self::TAG_LEN);
        // debug_assert_eq!(&self.gcm_key.nonce[12..16], &[0, 0, 0, 1]);

        let alen = aad.len();
        let clen = ciphertext_and_plaintext.len() - Self::TAG_LEN;
        let ciphertext = &mut ciphertext_and_plaintext[..clen];

        let mut counter_block = self.nonce.clone();
        // NOTE: 初始化 BlockCounter 计数器
        counter_block[12] = 0;
        counter_block[13] = 0;
        counter_block[14] = 0;
        counter_block[15] = 1;

        let mut base_ectr = counter_block.clone();
        self.cipher.encrypt(&mut base_ectr);

        let mut buf = [0u8; 16];

        self.hash_aad(aad, &mut buf);

        //////////// Update ///////////////
        for (block_index, chunk) in ciphertext.chunks_mut(Self::BLOCK_LEN).enumerate() {
            Self::block_num_inc(&mut counter_block);

            let mut ectr = counter_block.clone();
            self.cipher.encrypt(&mut ectr);

            for i in 0..chunk.len() {
                buf[i] ^= chunk[i];
                chunk[i] = ectr[i] ^ chunk[i];
            }

            self.ghash.ghash(&mut buf);
        }

        // Finalize
        let clen_bits: u64 = (clen as u64) * 8;
        let alen_bits: u64 = (alen as u64) * 8;
        
        let mut octets = [0u8; 16];
        let mut tag = [0u8; Self::TAG_LEN];
        tag[..Self::TAG_LEN].copy_from_slice(&base_ectr[..Self::TAG_LEN]);

        octets[0.. 8].copy_from_slice(&clen_bits.to_le_bytes());
        octets[8..16].copy_from_slice(&alen_bits.to_le_bytes());

        for i in 0..Self::BLOCK_LEN {
            buf[i] ^= octets[i];
        }

        self.ghash.ghash(&mut buf);

        for i in 0..Self::TAG_LEN {
            tag[i] ^= buf[i];
        }

        // Verify
        let input_tag = &ciphertext_and_plaintext[clen..clen + Self::TAG_LEN];
        bool::from(subtle::ConstantTimeEq::ct_eq(input_tag, &tag[..]))
    }
}





#[cfg(test)]
#[bench]
fn bench_aes128_gcm_with_16_bytes(b: &mut test::Bencher) {
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let iv = hex::decode("000000000000000000000000").unwrap();
    let aad = [0u8; 0];

    let mut cipher = Aes128Gcm::new(&key, &iv);

    b.bytes = Aes128Gcm::BLOCK_LEN as u64;
    b.iter(|| {
        let mut plaintext_and_ciphertext = [1u8; Aes128Gcm::BLOCK_LEN + Aes128Gcm::TAG_LEN];
        cipher.aead_encrypt(&aad, &mut plaintext_and_ciphertext);
        plaintext_and_ciphertext
    })
}
#[cfg(test)]
#[bench]
fn bench_aes128_gcm_with_64_bytes(b: &mut test::Bencher) {
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let iv = hex::decode("000000000000000000000000").unwrap();
    let aad = [0u8; 0];

    let mut cipher = Aes128Gcm::new(&key, &iv);

    b.bytes = 64;
    b.iter(|| {
        let mut plaintext_and_ciphertext = [1u8; 64 + Aes128Gcm::TAG_LEN];
        cipher.aead_encrypt(&aad, &mut plaintext_and_ciphertext);
        plaintext_and_ciphertext
    })
}
#[cfg(test)]
#[bench]
fn bench_aes128_gcm_with_1024_bytes(b: &mut test::Bencher) {
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let iv = hex::decode("000000000000000000000000").unwrap();
    let aad = [0u8; 0];

    let mut cipher = Aes128Gcm::new(&key, &iv);

    b.bytes = 1024;
    b.iter(|| {
        let mut plaintext_and_ciphertext = [1u8; 1024 + Aes128Gcm::TAG_LEN];
        cipher.aead_encrypt(&aad, &mut plaintext_and_ciphertext);
        plaintext_and_ciphertext
    })
}


#[test]
fn test_aes128_gcm() {
    // B   AES Test Vectors, (Page-29)
    // https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

    // Test  Case  1
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let iv = hex::decode("000000000000000000000000").unwrap();
    let aad = [0u8; 0];
    let plaintext = [0u8; 0];
    let mut ciphertext_and_tag = [0u8; 0 + Aes128Gcm::TAG_LEN];

    let mut cipher = Aes128Gcm::new(&key, &iv);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("58e2fccefa7e3061367f1d57a4e7455a").unwrap()[..]);


    // Test  Case  2
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let iv = hex::decode("000000000000000000000000").unwrap();
    let aad = [0u8; 0];
    let plaintext = hex::decode("00000000000000000000000000000000").unwrap();
    let plen = plaintext.len();
    let alen = aad.len();
    let mut plaintext_and_ciphertext = plaintext.clone();
    plaintext_and_ciphertext.resize(plen + Aes128Gcm::TAG_LEN, 0);

    let mut cipher = Aes128Gcm::new(&key, &iv);
    cipher.aead_encrypt(&aad, &mut plaintext_and_ciphertext);

    assert_eq!(&plaintext_and_ciphertext[..plen], &hex::decode("0388dace60b6a392f328c2b971b2fe78").unwrap()[..]);
    assert_eq!(&plaintext_and_ciphertext[plen..], &hex::decode("ab6e47d42cec13bdf53a67b21257bddf").unwrap()[..]);


    // Test  Case  3
    let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
    let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];
    let plaintext = hex::decode("d9313225f88406e5a55909c5aff5269a\
86a7a9531534f7da2e4c303d8a318a72\
1c3c0c95956809532fcf0e2449a6b525\
b16aedf5aa0de657ba637b391aafd255").unwrap();
    let plen = plaintext.len();
    let alen = aad.len();
    let mut plaintext_and_ciphertext = plaintext.clone();
    plaintext_and_ciphertext.resize(plen + Aes128Gcm::TAG_LEN, 0);

    let mut cipher = Aes128Gcm::new(&key, &iv);
    cipher.aead_encrypt(&aad, &mut plaintext_and_ciphertext);
    assert_eq!(&plaintext_and_ciphertext[..plen], &hex::decode("42831ec2217774244b7221b784d0d49c\
e3aa212f2c02a4e035c17e2329aca12e\
21d514b25466931c7d8f6a5aac84aa05\
1ba30b396a0aac973d58e091473f5985").unwrap()[..]);
    assert_eq!(&plaintext_and_ciphertext[plen..], &hex::decode("4d5c2af327cd64a62cf35abd2ba6fab4").unwrap()[..]);


    // Test  Case  4
    let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
    let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeef\
abaddad2").unwrap();
    let plaintext = hex::decode("d9313225f88406e5a55909c5aff5269a\
86a7a9531534f7da2e4c303d8a318a72\
1c3c0c95956809532fcf0e2449a6b525\
b16aedf5aa0de657ba637b39").unwrap();
    let plen = plaintext.len();
    let alen = aad.len();
    let mut plaintext_and_ciphertext = plaintext.clone();
    plaintext_and_ciphertext.resize(plen + Aes128Gcm::TAG_LEN, 0);

    let mut cipher = Aes128Gcm::new(&key, &iv);
    cipher.aead_encrypt(&aad, &mut plaintext_and_ciphertext);
    assert_eq!(&plaintext_and_ciphertext[..plen], &hex::decode("42831ec2217774244b7221b784d0d49c\
e3aa212f2c02a4e035c17e2329aca12e\
21d514b25466931c7d8f6a5aac84aa05\
1ba30b396a0aac973d58e091").unwrap()[..]);
    assert_eq!(&plaintext_and_ciphertext[plen..], &hex::decode("5bc94fbc3221a5db94fae95ae7121a47").unwrap()[..]);
}