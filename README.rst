Rust Crypto
===================

.. contents::


🚧 Interested but not implemented yet ✅ Implemented ❌ Not Interested

Benchmarks
----------

X86_64
~~~~~~
:Hardware: MacBook Pro(Retina, 15-inch, Mid 2015)
:CPU: 2.2 GHz Quad-Core Intel Core i7


OpenSSL::

    sm4-ecb                  92 mb/s
    aria-128-ecb            127 mb/s
    camellia-128-ecb        141 mb/s
    aes-128-ecb             636 mb/s

    aes-128-gcm             356 mb/s
    aes-128-ccm             133 mb/s
    aes-128-ocb             346 mb/s
    aria-128-gcm            103 mb/s
    aria-128-ccm             31 mb/s
    chacha20                538 mb/s
    chacha20-poly1305       417 mb/s

    sha256                   89 mb/s
    sm3                      68 mb/s


Rust Crypto::
    
    test blockcipher::bench_aes128_enc            ... bench:           3 ns/iter (+/- 0) = 5333 MB/s
    test blockcipher::bench_aes256_enc            ... bench:           6 ns/iter (+/- 1) = 2666 MB/s
    test blockcipher::bench_aria128_enc           ... bench:         347 ns/iter (+/- 33) = 46 MB/s
    test blockcipher::bench_aria256_enc           ... bench:         444 ns/iter (+/- 25) = 36 MB/s
    test blockcipher::bench_camellia128_enc       ... bench:         106 ns/iter (+/- 17) = 150 MB/s
    test blockcipher::bench_camellia256_enc       ... bench:         133 ns/iter (+/- 11) = 120 MB/s
    test blockcipher::bench_sm4_enc               ... bench:         210 ns/iter (+/- 27) = 76 MB/s

    test streamcipher::bench_chacha20             ... bench:         203 ns/iter (+/- 22) = 315 MB/s

    test aeadcipher::bench_aes128_ccm_enc         ... bench:          60 ns/iter (+/- 7) = 266 MB/s
    test aeadcipher::bench_aes128_gcm_enc         ... bench:          40 ns/iter (+/- 1) = 400 MB/s
    test aeadcipher::bench_aes128_gcm_siv_enc     ... bench:          75 ns/iter (+/- 3) = 213 MB/s
    test aeadcipher::bench_aes128_ocb_tag_128_enc ... bench:           9 ns/iter (+/- 1) = 1777 MB/s
    test aeadcipher::bench_aes_siv_cmac_256_enc   ... bench:         117 ns/iter (+/- 16) = 136 MB/s
    test aeadcipher::bench_chacha20_poly1305_enc  ... bench:         359 ns/iter (+/- 27) = 178 MB/s

    test hash::bench_sha256                       ... bench:         651 ns/iter (+/- 39) = 98 MB/s
    test hash::bench_sm3                          ... bench:         800 ns/iter (+/- 48) = 80 MB/s



AArch64
~~~~~~~
:Platform: Huawei Cloud - Kunpeng General Computing-plus KC1 ECS （kc1.small.1 | 1vCPUs | 1GB）
:CPU: Huawei Kunpeng 920 2.6GHz
:OS: Debian 10.2.0 64bit for ARM


OpenSSL::

    sm4-ecb                  73 mb/s
    aria-128-ecb             87 mb/s
    camellia-128-ecb        100 mb/s
    aes-128-ecb             577 mb/s
    aes-128-gcm             342 mb/s
    aes-128-ccm             133 mb/s
    aes-128-ocb             318 mb/s
    aria-128-gcm             79 mb/s
    aria-128-ccm             21 mb/s
    chacha20                377 mb/s
    chacha20-poly1305       312 mb/s
    sm3                      84 mb/s
    sha256                  190 mb/s


Rust Crypto::

    test aeadcipher::bench_aes128_ccm_enc         ... bench:          25 ns/iter (+/- 0) = 640 MB/s
    test aeadcipher::bench_aes128_gcm_enc         ... bench:          27 ns/iter (+/- 0) = 592 MB/s
    test aeadcipher::bench_aes128_gcm_siv_enc     ... bench:          79 ns/iter (+/- 0) = 202 MB/s
    test aeadcipher::bench_aes128_ocb_tag_128_enc ... bench:          21 ns/iter (+/- 0) = 761 MB/s
    test aeadcipher::bench_aes_siv_cmac_256_enc   ... bench:          63 ns/iter (+/- 0) = 262 MB/s
    test aeadcipher::bench_chacha20_poly1305_enc  ... bench:         436 ns/iter (+/- 7) = 146 MB/s
    test blockcipher::bench_aes128_enc            ... bench:           6 ns/iter (+/- 0) = 2666 MB/s
    test blockcipher::bench_aes256_enc            ... bench:          10 ns/iter (+/- 0) = 1600 MB/s
    test blockcipher::bench_aria128_enc           ... bench:         289 ns/iter (+/- 2) = 55 MB/s
    test blockcipher::bench_aria256_enc           ... bench:         390 ns/iter (+/- 4) = 41 MB/s
    test blockcipher::bench_camellia128_enc       ... bench:         135 ns/iter (+/- 1) = 118 MB/s
    test blockcipher::bench_camellia256_enc       ... bench:         177 ns/iter (+/- 1) = 90 MB/s

    test blockcipher::bench_sm4_enc               ... bench:         434 ns/iter (+/- 3) = 36 MB/s
    test blockmode::cfb::bench_aes128_cfb128_enc  ... bench:          20 ns/iter (+/- 0) = 800 MB/s
    test blockmode::ofb::bench_aes128_ofb_enc     ... bench:          20 ns/iter (+/- 0) = 800 MB/s

    test hash::bench_sha256                       ... bench:         103 ns/iter (+/- 0) = 621 MB/s

    test hash::bench_sm3                          ... bench:       1,024 ns/iter (+/- 10) = 62 MB/s

    test mac::bench_ghash                         ... bench:           0 ns/iter (+/- 0) = 16000 MB/s
    test mac::bench_poly1305                      ... bench:          21 ns/iter (+/- 0) = 761 MB/s
    test mac::bench_polyval                       ... bench:           0 ns/iter (+/- 8) = 16000 MB/s

    test streamcipher::bench_chacha20             ... bench:         320 ns/iter (+/- 6) = 200 MB/s



Hardware Acceleration
---------------------
X86/X86-64:

*   ✅ AES
*   ✅ CLMUL
*   ❌ SHA（SHA1）
*   ✅ SHA（SHA2-256）

AArch64:

*   ✅ AES
*   ✅ PMULL
*   ❌ SHA1
*   ✅ SHA2 （SHA2-256）
*   ❌ SHA512 (SHA2-512)
*   ❌ SHA3
*   ❌ SM3
*   ❌ SM4

Digest Algorithms
-----------------
*   ✅ MD2
*   ✅ MD4
*   ✅ MD5
*   ❌ MD6
*   ✅ SHA1
*   ✅ SHA2-256
*   ✅ SHA2-384
*   ✅ SHA2-512
*   🚧 SHA3-256
*   🚧 SHA3-384
*   🚧 SHA3-512
*   ✅ SM3
*   ❌ BLAKE2b
*   ❌ BLAKE2s
*   ❌ BLAKE3
*   ❌ RIPEMD
*   ❌ Whirlpool
*   🚧 GOST

Symmetric Key Encryption (Block Alogrithms)
-------------------------------------------
*   ❌ DES
*   ❌ 3DES
*   ✅ RC2 (or: ARC2)
*   🚧 RC5
*   ❌ RC6
*   ✅ AES
*   ✅ SM4
*   ✅ Camellia
*   ✅ ARIA
*   🚧 GOST（Magma、Kuznyechik）
*   ❌ Blowfish
*   ❌ Twofish
*   ❌ Threefish

Stream Cipher Alogrithms
------------------------
*   ✅ RC4
*   ✅ Chacha20
*   🚧 ZUC (in Chinese: 祖冲之算法)


Asymmetric Cryptographic Algorithm
----------------------------------
*   ❌ RSA
*   ❌ ED25519
*   🚧 SM2 （基于椭圆曲线：签名算法、密钥交换算法、加密算法）
*   🚧 SM9 （基于离散对数的机制：签名算法、密钥交换算法、加密算法）

Authenticated Encryption (AE) Algorithms
----------------------------------------
*   ✅ Chacha20Poly1305 (RFC7539)
*   🚧 Chacha20Poly1305OpenSSH
*   ✅ AES-CCM
*   ✅ AES-OCB
*   ✅ AES-GCM
*   ✅ AES-GCM-SIV
*   ✅ AES-SIV (AesSivCmac256、AesSivCmac384、AesSivCmac512)

*   ✅ CAMELLIA-CCM
*   ✅ CAMELLIA-GCM
*   ✅ CAMELLIA-GCM-SIV

*   ✅ ARIA-CCM
*   ✅ ARIA-GCM
*   ✅ ARIA-GCM-SIV

*   ✅ SM4-CCM
*   ✅ SM4-GCM
*   ✅ SM4-GCM-SIV


Encryption Algorithms
--------------------------
*   ✅ AES-ECB
*   ✅ AES-CBC
*   🚧 AES-PCBC
*   ✅ AES-CFB1
*   ✅ AES-CFB8
*   ✅ AES-CFB64
*   ✅ AES-CFB128
*   ✅ AES-OFB
*   ✅ AES-CTR

*   ✅ CAMELLIA-CBC
*   ✅ CAMELLIA-CFB1
*   ✅ CAMELLIA-CFB8
*   ✅ CAMELLIA-CFB64
*   ✅ CAMELLIA-CFB128
*   ✅ CAMELLIA-OFB
*   ✅ CAMELLIA-CTR

*   ✅ ARIA-CBC
*   ✅ ARIA-CFB1
*   ✅ ARIA-CFB8
*   ✅ ARIA-CFB64
*   ✅ ARIA-CFB128
*   ✅ ARIA-OFB
*   ✅ ARIA-CTR

*   ✅ SM4-CBC
*   ✅ SM4-CFB1
*   ✅ SM4-CFB8
*   ✅ SM4-CFB64
*   ✅ SM4-CFB128
*   ✅ SM4-OFB
*   ✅ SM4-CTR


Key Derivation Function (KDF)
-----------------------------
*   ✅ HKDF
*   🚧 Scrypt
*   ❌ PBKDF2

Message Authentication Code (MAC)
---------------------------------
*   ✅ HMAC
*   ✅ Poly1305
*   ✅ GMAC
*   ✅ CBC-Mac
*   ✅ CMac

Others
------
*   🚧 bcrypt
