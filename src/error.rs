
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct InvalidBlockLen;
impl std::error::Error for InvalidBlockLen { }

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct InvalidKeyLen;
impl std::error::Error for InvalidKeyLen { }

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct InvalidNonceLen;
impl std::error::Error for InvalidNonceLen { }

// UnexpectedEof
// Exhausted

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct AuthenticationTagMismatch;
impl std::error::Error for AuthenticationTagMismatch { }


