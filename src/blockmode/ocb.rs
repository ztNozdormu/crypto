// The OCB Authenticated-Encryption Algorithm
// https://tools.ietf.org/html/rfc7253
// 
// OCB: A Block-Cipher Mode of Operation for Efficient Authenticated Encryption
// https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/ocb/ocb-spec.pdf
use super::dbl;
use crate::mem::Zeroize;
use crate::mem::constant_time_eq;
use crate::util::xor_si128_inplace;
use crate::blockcipher::{Aes128, Aes192, Aes256};



const MASK_1: u8 = 0b1000_0000;
const MASK_2: u8 = 0b0100_0000;
const MASK_3: u8 = 0b0010_0000;
const MASK_4: u8 = 0b0001_0000;
const MASK_5: u8 = 0b0000_1000;
const MASK_6: u8 = 0b0000_0100;
const MASK_7: u8 = 0b0000_0010;
const MASK_8: u8 = 0b0000_0001;


macro_rules! impl_block_cipher_with_ocb_mode {
    ($name:tt, $cipher:tt, $tlen:tt) => {

        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
            table: [[u8; Self::BLOCK_LEN]; 32],
        }
        
        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.cipher.zeroize();
                self.table.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl $name {
            pub const KEY_LEN: usize   = $cipher::KEY_LEN;
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const TAG_LEN: usize   = $tlen;

            // P_MAX, A_MAX, and C_MAX are all unbounded
            pub const A_MAX: usize = usize::MAX;
            pub const P_MAX: usize = usize::MAX - Self::TAG_LEN;
            pub const C_MAX: usize = usize::MAX; // 2^36 + 16
            pub const N_MIN: usize =  1;
            pub const N_MAX: usize = 15;

            const STRETCH_LEN: usize = Self::BLOCK_LEN + 8;


            pub fn new(key: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);
                assert_eq!(Self::BLOCK_LEN, 16);
                
                let cipher = $cipher::new(key);

                // L_*, L_$, L_0, L_1, L_2, ..., L_29
                let mut table = [[0u8; Self::BLOCK_LEN]; 32];
                let mut double = [0u8; Self::BLOCK_LEN];
                cipher.encrypt(&mut double);

                table[0] = double;
                for i in 1..32 {
                    double = dbl(u128::from_be_bytes(double)).to_be_bytes();
                    table[i] = double;
                }

                Self {
                    cipher,
                    table,
                }
            }

            #[inline]
            fn calc_offset_0(&self, nonce: &[u8]) -> [u8; Self::BLOCK_LEN] {
                assert!(nonce.len() >= Self::N_MIN && nonce.len() <= Self::N_MAX);

                let nlen = nonce.len();
                let nlen_bits = nlen * 8;

                // Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N
                let mut nonce_ = [0u8; Self::BLOCK_LEN];
                nonce_[16 - nlen..].copy_from_slice(&nonce);

                nonce_[0] = ((Self::TAG_LEN as u8 * 8) % 128) << 1;
                nonce_[16 - nlen - 1] |= 0x01;

                let bottom = (nonce_[15] & 0b0011_1111) as usize;

                // Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6))
                let mut ktop = nonce_.clone();
                ktop[15] &= 0b1100_0000;
                self.cipher.encrypt(&mut ktop);

                // Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
                // ktop || ktop[0..8] || ktop[1..9]
                let mut stretch = [0u8; Self::STRETCH_LEN];
                stretch[..Self::BLOCK_LEN].copy_from_slice(&ktop);
                let mut tmp = [0u8; 8];
                for i in 0..8 {
                    tmp[i] = ktop[i] ^ ktop[i + 1];
                }
                stretch[Self::BLOCK_LEN..Self::STRETCH_LEN].copy_from_slice(&tmp);

                let mut stretch_bits = [false; Self::STRETCH_LEN * 8];
                for i in 0..Self::STRETCH_LEN {
                    let byte = stretch[i];
                    stretch_bits[i * 8 + 0] = byte & MASK_1 != 0;
                    stretch_bits[i * 8 + 1] = byte & MASK_2 != 0;
                    stretch_bits[i * 8 + 2] = byte & MASK_3 != 0;
                    stretch_bits[i * 8 + 3] = byte & MASK_4 != 0;
                    stretch_bits[i * 8 + 4] = byte & MASK_5 != 0;
                    stretch_bits[i * 8 + 5] = byte & MASK_6 != 0;
                    stretch_bits[i * 8 + 6] = byte & MASK_7 != 0;
                    stretch_bits[i * 8 + 7] = byte & MASK_8 != 0;
                }

                // Offset_0 = Stretch[1+bottom..128+bottom]
                let mut offset_0 = [0u8; Self::BLOCK_LEN];
                let mut offset_0_bits = [false; Self::BLOCK_LEN * 8];
                let slice = &stretch_bits[bottom..Self::BLOCK_LEN * 8 + bottom];
                assert_eq!(slice.len(), Self::BLOCK_LEN * 8);
                offset_0_bits.copy_from_slice(slice);

                for (i, bits) in offset_0_bits.chunks(8).enumerate() {
                    let mut byte = 0u8;
                    for bit in bits.iter() {
                        byte <<= 1;
                        if *bit {
                            byte |= 1;
                        }
                    }
                    offset_0[i] = byte;
                }

                offset_0
            }

            // 4.1.  Processing Associated Data: HASH
            // https://tools.ietf.org/html/rfc7253#section-4.1
            #[inline]
            fn hash(&self, aad: &[u8]) -> [u8; Self::BLOCK_LEN] {
                let alen = aad.len();

                let mut sum = [0u8; Self::BLOCK_LEN];
                let mut offset = [0u8; Self::BLOCK_LEN];
                let mut block_idx = 1usize;
                for chunk in aad.chunks_exact(Self::BLOCK_LEN) {
                    let ntz = block_idx.trailing_zeros() as usize;
                    let double;
                    if ntz > 30 {
                        let mut tmp = self.table[31];
                        for _ in 30..ntz {
                            tmp = dbl(u128::from_be_bytes(tmp)).to_be_bytes();
                        }
                        double = tmp;
                    } else {
                        double = self.table[ntz + 2];
                    }

                    xor_si128_inplace(&mut offset, &double);

                    let mut block = offset.clone();
                    xor_si128_inplace(&mut block, chunk);

                    self.cipher.encrypt(&mut block);
                    xor_si128_inplace(&mut sum, &block);

                    block_idx += 1;
                }

                block_idx -= 1;

                if alen % Self::BLOCK_LEN > 0 {
                    // Last Block
                    let remainder = &aad[block_idx * Self::BLOCK_LEN..];

                    let double_z1 = self.table[0];
                    xor_si128_inplace(&mut offset, &double_z1);

                    let mut block = [0u8; Self::BLOCK_LEN];
                    block[..remainder.len()].copy_from_slice(remainder);
                    block[remainder.len()] = 0x80;

                    xor_si128_inplace(&mut block, &offset);

                    self.cipher.encrypt(&mut block);

                    xor_si128_inplace(&mut sum, &block);
                } else {
                    // Process any final partial block; compute final hash value

                }

                sum
            }
            
            pub fn encrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) {
                debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

                let plen = aead_pkt.len() - Self::TAG_LEN;
                let (plaintext_and_ciphertext, tag_out) = aead_pkt.split_at_mut(plen);

                self.encrypt_slice_detached(nonce, aad, plaintext_and_ciphertext, tag_out)
            }

            pub fn decrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
                debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

                let clen = aead_pkt.len() - Self::TAG_LEN;
                let (ciphertext_and_plaintext, tag_in) = aead_pkt.split_at_mut(clen);

                self.decrypt_slice_detached(nonce, aad, ciphertext_and_plaintext, &tag_in)
            }


            pub fn encrypt_slice_detached(&self, nonce: &[u8], aad: &[u8], plaintext_and_ciphertext: &mut [u8], tag_out: &mut [u8]) {
                let alen = aad.len();
                let plen = plaintext_and_ciphertext.len();
                let tlen = tag_out.len();

                debug_assert!(alen <= Self::A_MAX);
                debug_assert!(plen <= Self::P_MAX);
                debug_assert!(tlen == Self::TAG_LEN);

                let mut offset = self.calc_offset_0(nonce);
                let mut checksum = [0u8; Self::BLOCK_LEN];

                let mut block_idx = 1usize;
                for chunk in plaintext_and_ciphertext.chunks_exact_mut(Self::BLOCK_LEN) {
                    // Process any whole blocks
                    let ntz = block_idx.trailing_zeros() as usize;
                    let double;
                    if ntz > 30 {
                        let mut tmp = self.table[31];
                        for _ in 30..ntz {
                            tmp = dbl(u128::from_be_bytes(tmp)).to_be_bytes();
                        }
                        double = tmp;
                    } else {
                        double = self.table[ntz + 2];
                    }

                    xor_si128_inplace(&mut offset, &double);

                    let mut block = offset.clone();
                    xor_si128_inplace(&mut block, chunk);

                    self.cipher.encrypt(&mut block);

                    xor_si128_inplace(&mut checksum, chunk);
                    xor_si128_inplace(&mut block, &offset);
                    chunk.copy_from_slice(&block);

                    block_idx += 1;
                }

                block_idx -= 1;

                if plen % Self::BLOCK_LEN > 0 {
                    // Last Block
                    let remainder = &mut plaintext_and_ciphertext[block_idx * Self::BLOCK_LEN..];

                    let double_z1 = self.table[0];
                    xor_si128_inplace(&mut offset, &double_z1);

                    let mut pad = offset.clone();
                    self.cipher.encrypt(&mut pad);

                    for i in 0..remainder.len() {
                        pad[i] ^= remainder[i];
                    }

                    for i in 0..remainder.len() {
                        checksum[i] ^= remainder[i];
                        remainder[i] = pad[i];
                    }
                    checksum[remainder.len()] ^= 0x80;
                }

                let double_z2 = self.table[1];
                xor_si128_inplace(&mut checksum, &offset);
                xor_si128_inplace(&mut checksum, &double_z2);

                let mut tag_block = checksum;
                self.cipher.encrypt(&mut tag_block);

                let aad_hash = self.hash(aad);
                xor_si128_inplace(&mut tag_block, &aad_hash);

                tag_out.copy_from_slice(&tag_block[..Self::TAG_LEN]);
            }

            pub fn decrypt_slice_detached(&self, nonce: &[u8], aad: &[u8], ciphertext_and_plaintext: &mut [u8], tag_in: &[u8]) -> bool {
                let alen = aad.len();
                let clen = ciphertext_and_plaintext.len();
                let tlen = tag_in.len();

                debug_assert!(alen <= Self::A_MAX);
                debug_assert!(clen <= Self::P_MAX);
                debug_assert!(tlen == Self::TAG_LEN);

                let mut offset = self.calc_offset_0(nonce);
                let mut checksum = [0u8; Self::BLOCK_LEN];

                let mut block_idx = 1usize;
                for chunk in ciphertext_and_plaintext.chunks_exact_mut(Self::BLOCK_LEN) {
                    // Process any whole blocks
                    let ntz = block_idx.trailing_zeros() as usize;
                    let double;
                    if ntz > 30 {
                        let mut tmp = self.table[31];
                        for _ in 30..ntz {
                            tmp = dbl(u128::from_be_bytes(tmp)).to_be_bytes();
                        }
                        double = tmp;
                    } else {
                        double = self.table[ntz + 2];
                    }

                    xor_si128_inplace(&mut offset, &double);
                    xor_si128_inplace(chunk, &offset);

                    self.cipher.decrypt(chunk);

                    xor_si128_inplace(chunk, &offset);
                    xor_si128_inplace(&mut checksum, &chunk);

                    block_idx += 1;
                }

                block_idx -= 1;

                if clen % Self::BLOCK_LEN > 0 {
                    // Last Block
                    let remainder = &mut ciphertext_and_plaintext[block_idx * Self::BLOCK_LEN..];

                    let double_z1 = self.table[0];
                    xor_si128_inplace(&mut offset, &double_z1);

                    let mut pad = offset.clone();
                    self.cipher.encrypt(&mut pad);

                    for i in 0..remainder.len() {
                        remainder[i] ^= pad[i];
                        checksum[i] ^= remainder[i];
                    }
                    checksum[remainder.len()] ^= 0x80;
                }

                xor_si128_inplace(&mut checksum, &offset);
                xor_si128_inplace(&mut checksum, &self.table[1]);
                
                let mut tag_block = checksum;
                self.cipher.encrypt(&mut tag_block);

                let aad_hash = self.hash(aad);
                xor_si128_inplace(&mut tag_block, &aad_hash);

                // Verify
                constant_time_eq(tag_in, &tag_block[..Self::TAG_LEN])
            }
        }
    }
}


impl_block_cipher_with_ocb_mode!(Aes128OcbTag128, Aes128, 16); // TAG-LEN=16
impl_block_cipher_with_ocb_mode!(Aes128OcbTag96,  Aes128, 12); // TAG-LEN=12
impl_block_cipher_with_ocb_mode!(Aes128OcbTag64,  Aes128, 8);  // TAG-LEN=8

impl_block_cipher_with_ocb_mode!(Aes192OcbTag128, Aes192, 16); // TAG-LEN=16
impl_block_cipher_with_ocb_mode!(Aes192OcbTag96,  Aes192, 12); // TAG-LEN=12
impl_block_cipher_with_ocb_mode!(Aes192OcbTag64,  Aes192, 8);  // TAG-LEN=8

impl_block_cipher_with_ocb_mode!(Aes256OcbTag128, Aes256, 16); // TAG-LEN=16
impl_block_cipher_with_ocb_mode!(Aes256OcbTag96,  Aes256, 12); // TAG-LEN=12
impl_block_cipher_with_ocb_mode!(Aes256OcbTag64,  Aes256, 8);  // TAG-LEN=8



#[test]
fn test_aes128_ocb_tag128_dec() {
    let key       = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let nonce     = hex::decode("BBAA9988776655443322110F").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F2021222324252627").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);

    let mut ciphertext_and_tag = hex::decode("4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15\
A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95\
A98CA5F3000B1479").unwrap();
    let ret = cipher.decrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(ret, true);
    assert_eq!(&ciphertext_and_tag[..plen], &plaintext);
}

#[test]
fn test_aes128_ocb_tag128_enc() {
    // Appendix A.  Sample Results
    // https://tools.ietf.org/html/rfc7253#appendix-A
    let key       = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();

    let nonce     = hex::decode("BBAA99887766554433221100").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("785407BFFFC8AD9EDCC5520AC9111EE6").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221101").unwrap();
    let aad       = hex::decode("0001020304050607").unwrap();
    let plaintext = hex::decode("0001020304050607").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221102").unwrap();
    let aad       = hex::decode("0001020304050607").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("81017F8203F081277152FADE694A0A00").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221103").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("0001020304050607").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221104").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5\
701C1CCEC8FC3358").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221105").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("8CF761B6902EF764462AD86498CA6B97").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221106").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436B\
DF06D8FA1ECA343D").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221107").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("1CA2207308C87C010756104D8840CE1952F09673A448A122\
C92C62241051F57356D7F3C90BB0E07F").unwrap()[..]);
    
    let nonce     = hex::decode("BBAA99887766554433221108").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("6DC225A071FC1B9F7C69F93B0F1E10DE").unwrap()[..]);


    let nonce     = hex::decode("BBAA99887766554433221109").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3C\
E725F32494B9F914D85C0B1EB38357FF").unwrap()[..]);


    let nonce     = hex::decode("BBAA9988776655443322110A").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("BD6F6C496201C69296C11EFD138A467ABD3C707924B964DE\
AFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240").unwrap()[..]);


    let nonce     = hex::decode("BBAA9988776655443322110B").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("FE80690BEE8A485D11F32965BC9D2A32").unwrap()[..]);
    

    let nonce     = hex::decode("BBAA9988776655443322110C").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF4\
6040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF").unwrap()[..]);


    let nonce     = hex::decode("BBAA9988776655443322110D").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F2021222324252627").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F2021222324252627").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("D5CA91748410C1751FF8A2F618255B68A0A12E093FF45460\
6E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483\
A7035490C5769E60").unwrap()[..]);


    let nonce     = hex::decode("BBAA9988776655443322110E").unwrap();
    let aad       = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F2021222324252627").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("C5CD9D1850C141E358649994EE701B68").unwrap()[..]);

    
    let nonce     = hex::decode("BBAA9988776655443322110F").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617\
18191A1B1C1D1E1F2021222324252627").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128OcbTag128::TAG_LEN, 0);
    let cipher = Aes128OcbTag128::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15\
A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95\
A98CA5F3000B1479").unwrap()[..]);
}