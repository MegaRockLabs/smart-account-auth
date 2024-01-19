use saa_schema::*;
use hex::FromHexError;
use thiserror::Error;
use bech32::Error as Bech32Error;


#[wasm_serde]
#[derive(Error)]
pub enum AddressError {
    #[error("Address must not be empty")]
    Empty,

    #[error("Hex Decoding Error: {0}")]
    Hex(String),

    #[error("Bech32 Deriving Error: {0}")]
    Bech32(String),

    #[error("{0}")]
    InvalidLength(String),

    #[error("Address error: {0}")]
    Generic(String),

    #[error("{0}")]
    GenericNoPrefix(String),
}


impl AddressError {
    pub fn generic<M: Into<String>>(msg: M) -> Self {
        AddressError::Generic(msg.into())
    }

    pub fn generic_no_prefix<M: Into<String>>(msg: M) -> Self {
        AddressError::GenericNoPrefix(msg.into())
    }
}

impl From<FromHexError> for AddressError {
    fn from(err: FromHexError) -> Self {
        Self::Hex(err.to_string())
    }
}

impl From<Bech32Error> for AddressError {
    fn from(err: Bech32Error) -> Self {
        Self::Bech32(err.to_string())
    }
}


#[wasm_serde]
#[derive(Error)]
pub enum AuthError {

    #[error("{0}")]
    Address(#[from] AddressError),

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
    
    #[error("Semver parsing error: {0}")]
    SemVer(String),
}


impl AuthError {
    pub fn generic<M: Into<String>>(msg: M) -> Self {
        AuthError::Generic(msg.into())
    }
}

impl From<cosmwasm_crypto::CryptoError> for AuthError {
    fn from(err: cosmwasm_crypto::CryptoError) -> Self {
        Self::Generic(err.to_string())
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