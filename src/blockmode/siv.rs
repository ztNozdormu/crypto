// Synthetic Initialization Vector (SIV) Authenticated Encryption Using the Advanced Encryption Standard (AES)
// https://tools.ietf.org/html/rfc5297
// 
// AES-GCM-SIV: Specification and Analysis
// https://eprint.iacr.org/2017/168.pdf
// 


const C128: u64 = 0b1000_0111;

#[inline]
fn dbl(block: &mut [u8; 16]) {
    let mut a = u64::from_be_bytes([
        block[0], block[1], block[2], block[3], 
        block[4], block[5], block[6], block[7], 
    ]);
    let mut b = u64::from_be_bytes([
        block[ 8], block[ 9], block[10], block[11], 
        block[12], block[13], block[14], block[15], 
    ]);

    let c = b >> 63;
    let d = (a >> 63) * C128;

    a = (a << 1) ^ c;
    b = (b << 1) ^ d;

    block[0.. 8].copy_from_slice(&a.to_be_bytes());
    block[8..16].copy_from_slice(&b.to_be_bytes());
}

#[inline]
fn inv_dbl(block: &mut [u8; 16]) {
    let mut a = u64::from_be_bytes([
        block[0], block[1], block[2], block[3], 
        block[4], block[5], block[6], block[7], 
    ]);
    let mut b = u64::from_be_bytes([
        block[ 8], block[ 9], block[10], block[11], 
        block[12], block[13], block[14], block[15], 
    ]);

    let c = (a & 1) << 63;
    let d =  b & 1;

    a >>= 1;
    b >>= 1;
    b  ^= c;
    a  ^= d * (   1 << 63);
    b  ^= d * (C128 >>  1);

    block[0.. 8].copy_from_slice(&a.to_be_bytes());
    block[8..16].copy_from_slice(&b.to_be_bytes());
}


