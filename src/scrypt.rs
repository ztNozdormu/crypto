


// The scrypt Password-Based Key Derivation Function
// https://tools.ietf.org/html/rfc7914
// 
// https://en.wikipedia.org/wiki/Scrypt#Algorithm

use byteorder::{LE, BE, ByteOrder};

use std::convert::TryFrom;

