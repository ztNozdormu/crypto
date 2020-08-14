// Authenticated Encryption with Associated Data (AEAD) Parameters
// https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
// 
// Last Updated: 2019-04-18
// 
// Numeric ID   Name                        Reference
// 1            AEAD_AES_128_GCM            [RFC5116]
// 2            AEAD_AES_256_GCM            [RFC5116]
// 3            AEAD_AES_128_CCM            [RFC5116]
// 4            AEAD_AES_256_CCM            [RFC5116]
// 5            AEAD_AES_128_GCM_8          [RFC5282]
// 6            AEAD_AES_256_GCM_8          [RFC5282]
// 7            AEAD_AES_128_GCM_12         [RFC5282]
// 8            AEAD_AES_256_GCM_12         [RFC5282]
// 9            AEAD_AES_128_CCM_SHORT      [RFC5282]
// 10           AEAD_AES_256_CCM_SHORT      [RFC5282]
// 11           AEAD_AES_128_CCM_SHORT_8    [RFC5282]
// 12           AEAD_AES_256_CCM_SHORT_8    [RFC5282]
// 13           AEAD_AES_128_CCM_SHORT_12   [RFC5282]
// 14           AEAD_AES_256_CCM_SHORT_12   [RFC5282]
// 15           AEAD_AES_SIV_CMAC_256       [RFC5297]
// 16           AEAD_AES_SIV_CMAC_384       [RFC5297]
// 17           AEAD_AES_SIV_CMAC_512       [RFC5297]
// 18           AEAD_AES_128_CCM_8          [RFC6655]
// 19           AEAD_AES_256_CCM_8          [RFC6655]
// 20           AEAD_AES_128_OCB_TAGLEN128  [RFC7253, Section 3.1]
// 21           AEAD_AES_128_OCB_TAGLEN96   [RFC7253, Section 3.1]
// 22           AEAD_AES_128_OCB_TAGLEN64   [RFC7253, Section 3.1]
// 23           AEAD_AES_192_OCB_TAGLEN128  [RFC7253, Section 3.1]
// 24           AEAD_AES_192_OCB_TAGLEN96   [RFC7253, Section 3.1]
// 25           AEAD_AES_192_OCB_TAGLEN64   [RFC7253, Section 3.1]
// 26           AEAD_AES_256_OCB_TAGLEN128  [RFC7253, Section 3.1]
// 27           AEAD_AES_256_OCB_TAGLEN96   [RFC7253, Section 3.1]
// 28           AEAD_AES_256_OCB_TAGLEN64   [RFC7253, Section 3.1]
// 29           AEAD_CHACHA20_POLY1305      [RFC8439]
// 30           AEAD_AES_128_GCM_SIV        [RFC8452]
// 31           AEAD_AES_256_GCM_SIV        [RFC8452]
// 32-32767     Unassigned
// 32768-65535  Reserved for Private Use    [RFC5116]


// AEAD_AES_128_GCM_8   // TAG_LEN:  8
// AEAD_AES_128_GCM_12  // TAG_LEN: 12
// AEAD_AES_128_GCM     // TAG LEN: 16

// AEAD_AES_128_CCM          // NONCE-LEN=12 TAG-LEN=16 Q=3
// AEAD_AES_128_CCM_SHORT    // NONCE-LEN=11 TAG-LEN=16 Q=3
// AEAD_AES_128_CCM_SHORT_8  // NONCE-LEN=11 TAG-LEN= 8 Q=3
// AEAD_AES_128_CCM_SHORT_12 // NONCE-LEN=11 TAG-LEN=12 Q=3
// AEAD_AES_128_CCM_8        // NONCE-LEN=12 TAG-LEN= 8 Q=3

// Synthetic Initialization Vector (SIV) Authenticated Encryption
//          Using the Advanced Encryption Standard (AES)
// https://tools.ietf.org/html/rfc5297
// 
// AEAD_AES_SIV_CMAC_256
// AEAD_AES_SIV_CMAC_384
// AEAD_AES_SIV_CMAC_512

// AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption
// https://tools.ietf.org/html/rfc8452
// 
// AEAD_AES_128_GCM_SIV
// AEAD_AES_256_GCM_SIV

// Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
// AEAD_AES-GCM-128
// AEAD_AES-GCM-256


// ChaCha20 and Poly1305 for IETF Protocols
// https://tools.ietf.org/html/rfc8439
// 
// AEAD_CHACHA20_POLY1305
