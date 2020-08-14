
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct InvalidBlockLen;
impl std::fmt::Display for InvalidBlockLen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid Block Len")
    }
}
impl std::error::Error for InvalidBlockLen { }

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct InvalidKeyLen;
impl std::fmt::Display for InvalidKeyLen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid Key Len")
    }
}
impl std::error::Error for InvalidKeyLen { }

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct InvalidNonceLen;
impl std::fmt::Display for InvalidNonceLen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid Nonce Len")
    }
}
impl std::error::Error for InvalidNonceLen { }

// UnexpectedEof
// Exhausted

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct AuthenticationTagMismatch;
impl std::fmt::Display for AuthenticationTagMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Authentication Tag Mismatch")
    }
}
impl std::error::Error for AuthenticationTagMismatch { }



