Rust Crypto
===================

.. contents::


🚧 代表有兴趣开发、✅ 代表已经实现、❌ 代表没有兴趣实现。


硬件加速
-------------------------
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

摘要算法
--------------------------
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

分组对称加密算法
--------------------------
*   ❌ DES
*   ❌ 3DES
*   ✅ RC2 (又称：ARC2)
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

序列对称加密算法（流密码）
--------------------------
*   ✅ RC4
*   ✅ Chacha20
*   🚧 ZUC（祖冲之算法）


公私钥非对称加密算法
--------------------------
*   ❌ RSA
*   ❌ ED25519
*   🚧 SM2 （基于椭圆曲线：签名算法、密钥交换算法、加密算法）
*   🚧 SM9 （基于离散对数的机制：签名算法、密钥交换算法、加密算法）

认证加密算法（AE）
--------------------------
*   ✅ Chacha20Poly1305（IETF发布的版本）
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


非认证加密算法
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


密钥派生函数（KDF）
--------------------------
*   ✅ HKDF
*   🚧 Scrypt
*   ❌ PBKDF2

消息认证码（MAC）
--------------------------
*   ✅ HMAC
*   ✅ Poly1305
*   ✅ GMAC
*   ✅ CBC-Mac
*   ✅ CMac

其它加密算法
--------------------------
*   🚧 bcrypt

