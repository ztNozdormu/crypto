use crate::mem::Zeroize;
use crate::hash::Md5;


/// Table cipher
#[derive(Clone)]
pub struct TableCipher {
    ebox: [u8; Self::TABLE_SIZE], // Encrypt
    dbox: [u8; Self::TABLE_SIZE], // Decrypt
}

impl Zeroize for TableCipher {
    fn zeroize(&mut self) {
        self.ebox.zeroize();
        self.dbox.zeroize();
    }
}

impl Drop for TableCipher {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for TableCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("TableCipher").finish()
    }
}

impl TableCipher {
    const TABLE_SIZE: usize = 256;
    
    pub fn new(key: &[u8]) -> Self {
        let h = Md5::oneshot(key);
        let a = u64::from_le_bytes([
            h[0], h[1], h[2], h[3], 
            h[4], h[5], h[6], h[7], 
        ]);

        let mut table = [0u64; Self::TABLE_SIZE];
        for i in 0..Self::TABLE_SIZE {
            table[i] = i as u64;
        }

        for i in 1..1024 {
            table.sort_by(|x, y| (a % (*x + i)).cmp(&(a % (*y + i))))
        }

        // EK
        let mut ebox = [0u8; Self::TABLE_SIZE];
        for i in 0..Self::TABLE_SIZE {
            ebox[i] = table[i] as u8;
        }

        // DK
        let mut dbox = [0u8; Self::TABLE_SIZE];
        for i in 0..Self::TABLE_SIZE {
            dbox[table[i] as usize] = i as u8;
        }

        Self { ebox, dbox }
    }

    pub fn encrypt_slice(&self, plaintext_and_ciphertext: &mut [u8]) {
        let plen = plaintext_and_ciphertext.len();
        for i in 0..plen {
            let v = plaintext_and_ciphertext[i];
            plaintext_and_ciphertext[i] = self.ebox[v as usize];
        }
    }
    
    pub fn decrypt_slice(&self, ciphertext_and_plaintext: &mut [u8]) {
        let clen = ciphertext_and_plaintext.len();
        for i in 0..clen {
            let v = ciphertext_and_plaintext[i];
            ciphertext_and_plaintext[i] = self.dbox[v as usize];
        }
    }
}


#[test]
fn test_table_cipher() {
    let key: &[u8]       = b"keykeykk";
    let plaintext: &[u8] = b"hello world";


    let mut ciphertext = plaintext.to_vec();
    let cipher = TableCipher::new(key);
    cipher.encrypt_slice(&mut ciphertext);

    let mut cleartext = ciphertext.clone();
    let cipher = TableCipher::new(key);
    cipher.decrypt_slice(&mut cleartext);
    
    assert_eq!(&cleartext[..], plaintext);
}