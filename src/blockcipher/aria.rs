// A Description of the ARIA Encryption Algorithm
// https://tools.ietf.org/html/rfc5794
// 
// Korean Standard Block Cipher Algorithm Block Cipher Algorithm ARIA
// http://210.104.33.10/ARIA/index-e.html
// 
// Specification of ARIA
// http://210.104.33.10/ARIA/doc/ARIA-specification-e.pdf


// C code
// https://www.oryx-embedded.com/doc/aria_8c_source.html
// 
// C++ code
// https://github.com/SidRama/ARIA-Cryptosystem/blob/master/aria.cpp

// C code
// https://github.com/ARMmbed/mbedtls/blob/development/library/aria.c

// 
// Block size: 128 bits
// Key sizes: 128/192/256 bits (same as AES)
// Overall structure: Involutional Substitution-Permutation Network.
// Number of rounds: 12/14/16 (depending on the key size) 
// 

// 韩国技术标准局（KATS）提供的 C、C++、Java 代码:
// https://seed.kisa.or.kr/kisa/Board/19/detailView.do

const BLOCK_LEN: usize = 16;



