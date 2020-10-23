#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import platform
import subprocess
import re


if platform.system() == "Linux":
    OPENSSL = "openssl"
elif platform.system() == "Darwin":
    OPENSSL = "/usr/local/opt/openssl/bin/openssl"
else:
    raise NotImplementedError("Ooops ...")


"""
$ openssl speed -bytes 16 -evp aes-128-ccm

Doing aes-128-ccm for 3s on 16 size blocks: 24785630 aes-128-ccm's in 2.97s
OpenSSL 1.1.1g  21 Apr 2020
built on: Tue Apr 21 13:30:00 2020 UTC
options:bn(64,64) rc4(16x,int) des(int) aes(partial) idea(int) blowfish(ptr)
compiler: clang -fPIC -arch x86_64 -O3 -Wall -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM -DMD5_ASM -DAESNI_ASM -DVPAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPOLY1305_ASM -D_REENTRANT -DNDEBUG
The 'numbers' are in 1000s of bytes per second processed.
type             16 bytes
aes-128-ccm     133525.28k
"""
def shell(cmd):
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    process.wait()

    if process.returncode == 0:
        output = process.stdout.read().decode("utf8")
        return output
    else:
        if process.stderr:
            print(process.stderr.read())
            return None

def main():
    cmd_list = [
        # ECB 分组相对于直接使用 Block Cipher 本身，这样可以测试 Aes128/Sm4 这些 BlockCipher 的性能。
        [OPENSSL, "speed", "-bytes", "16", "-evp", "sm4-ecb"],
        [OPENSSL, "speed", "-bytes", "16", "-evp", "aria-ecb"],
        [OPENSSL, "speed", "-bytes", "16", "-evp", "camellia-ecb"],
        [OPENSSL, "speed", "-bytes", "16", "-evp", "aes-128-ecb"],

        [OPENSSL, "speed", "-bytes", "16", "-evp", "aes-128-gcm"],
        [OPENSSL, "speed", "-bytes", "16", "-evp", "aes-128-ccm"],
        [OPENSSL, "speed", "-bytes", "16", "-evp", "aes-128-ocb"],
        
        [OPENSSL, "speed", "-bytes", "16", "-evp", "aria-128-gcm"],
        [OPENSSL, "speed", "-bytes", "16", "-evp", "aria-128-ccm"],

        [OPENSSL, "speed", "-bytes", "64", "-evp", "chacha20"],
        [OPENSSL, "speed", "-bytes", "64", "-evp", "chacha20-poly1305"],
        
        [OPENSSL, "speed", "-bytes", "64", "-evp", "sha256"],
    ]
    res = []

    for cmd in cmd_list:
        output = shell(cmd)
        if output:
            tmp = output.split("\n")
            if len(tmp) > 0:
                line = tmp[-2]
                res.append(line.strip())
    for line in res:
        tmp = line.split(" ")
        cipher = tmp[0]
        report = int(float(tmp[-1].replace("k", ""))) // 1024 # MB
        print("%s    %d MB/s" % (cipher.ljust(15, " "), report))
        

if __name__ == '__main__':
    main()