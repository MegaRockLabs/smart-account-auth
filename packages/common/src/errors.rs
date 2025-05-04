#[cfg(any(feature = "std", not(feature = "substrate")))]
use {thiserror::Error, saa_schema::wasm_serde};
use {crate::String, std::string::FromUtf8Error};


#[cfg(all(not(feature = "std"), feature = "substrate"))]
#[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
pub enum AuthError {
    NoCredentials,
    InvalidLength(String),
    RecoveryParam,
    RecoveryMismatch,
    InvalidSignedData,
    Signature(String),
    Recovery(String),
    Generic(String),
    Crypto(String),
    SemVer(String),
}



#[cfg(any(feature = "std", not(feature = "substrate")))]
#[wasm_serde]
#[derive(Error)]
pub enum AuthError {

    #[error("No credentials provided or credentials are partially missing")]
    NoCredentials,

    #[error("{0}")]
    MissingData(String),

    #[error("Expected: {0};  Received: {1}")]
    InvalidLength(u16, u16),

    #[error("Values of v other than 27 and 28 not supported. Replay protection (EIP-155) cannot be used here.")]
    RecoveryParam,
    
    #[error("Error recovering from the signature: Addresses do not match")]
    RecoveryMismatch,

    #[error("The provided credential was meant for a different chain")]
    ChainIdMismatch,

    #[error("The provided credential was meant for a different contract address")]
    ContractMismatch,

    #[error("The provided nonce has already been used")]
    NonceUsed,

    #[error("The given credential was not found on this account")]
    NotFound, 

    #[error("The given credential already exists on this account")]
    AlreadyExists,

    #[error("At least one of the credential must be usable for verifications")]
    NoVerifying,

    #[error("Wrong account number")]
    DifferentNonce,

    #[error("The signed data is expected to be a replay attach protection envelope")]
    InvalidSignedData,

    #[error("Passkey challenge must be base64url to base64 encoded string")]
    PasskeyChallenge,

    #[error("{0}")]
    Signature(String),

    #[error("{0}")]
    Recovery(String),

    #[error("{0}")]
    Generic(String),

    #[error("{0}")]
    Crypto(String),
    
    #[error("Semver parsing error: {0}")]
    SemVer(String),
}


impl AuthError {
    pub fn generic<M: Into<String>>(msg: M) -> Self {
        AuthError::Generic(msg.into())
    }
}

impl From<bech32::primitives::hrp::Error> for AuthError {
    fn from(err: bech32::primitives::hrp::Error) -> Self {
        Self::Crypto(err.to_string())
    }
}


impl From<bech32::EncodeError> for AuthError {
    fn from(err: bech32::EncodeError) -> Self {
        Self::Crypto(err.to_string())
    }
}


#[cfg(feature = "std")]
impl From<FromUtf8Error> for AuthError {
    fn from(err: FromUtf8Error) -> Self {
        Self::Recovery(err.to_string())
    }
}


#[cfg(feature = "native")] 
impl From<cosmwasm_crypto::CryptoError> for AuthError {
    fn from(err: cosmwasm_crypto::CryptoError) -> Self {
        Self::Crypto(err.to_string())
    }
}

#[cfg(feature = "wasm")] 
mod implementation{
    use crate::AuthError;

    impl From<crate::wasm::RecoverPubkeyError> for AuthError {
        fn from(err: crate::wasm::RecoverPubkeyError) -> Self {
            Self::Recovery(err.to_string())
        }
    }

    impl From<crate::wasm::StdError> for AuthError {
        fn from(err: crate::wasm::StdError) -> Self {
            Self::Generic(err.to_string())
        }
    }

    impl From<crate::wasm::VerificationError> for AuthError {
        fn from(err: crate::wasm::VerificationError) -> Self {
            Self::Crypto(err.to_string())
        }
    }
}
