#[cfg(any(feature = "std", not(feature = "substrate")))]
use {thiserror::Error, saa_schema::wasm_serde};


#[cfg(all(not(feature = "std"), feature = "substrate"))]
type String = ink::prelude::string::String;


#[cfg(all(not(feature = "std"), feature = "substrate"))]
#[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
pub enum AuthError {
    NoCredentials,
    InvalidLength(String),
    RecoveryParam,
    RecoveryMismatch,
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
    InvalidLength(String),

    #[error("Values of v other than 27 and 28 not supported. Replay protection (EIP-155) cannot be used here.")]
    RecoveryParam,
    
    #[error("Error recovering from the signature: Addresses do not match")]
    RecoveryMismatch,

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



#[cfg(feature = "cosmwasm")] 
impl From<cosmwasm_std::RecoverPubkeyError> for AuthError {
    fn from(err: cosmwasm_std::RecoverPubkeyError) -> Self {
        Self::Recovery(err.to_string())
    }
}

#[cfg(feature = "cosmwasm")] 
impl From<cosmwasm_std::StdError> for AuthError {
    fn from(err: cosmwasm_std::StdError) -> Self {
        Self::Generic(err.to_string())
    }
}

#[cfg(feature = "cosmwasm")] 
impl From<cosmwasm_std::VerificationError> for AuthError {
    fn from(err: cosmwasm_std::VerificationError) -> Self {
        Self::Generic(err.to_string())
    }
}

/* impl From<ed25519_zebra::Error> for AuthError {
    fn from(err: ed25519_zebra::Error) -> Self {
        Self::Crypto(err.to_string())
    }
} */