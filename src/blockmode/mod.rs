
// Recommendation for Block Cipher Modes of Operation (ECB/CBC/CFB/OFB/CTR)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

// NOTE: ECB 分组工作模式没有实现的必要，因为 Cipher（如 AES）本身就是分组的。
//       所以在 ECB 工作模式下，和直接使用 AES128.encrypt(&block) 没有区别。
pub mod cbc;
pub mod cfb;
pub mod ofb;
pub mod ctr;

// pub mod ccm;
pub mod gcm;
// pub mod siv;