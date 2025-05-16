
mod std_mod {
    use saa_schema::saa_error;

    #[cfg(feature = "session")]
    #[saa_error]
    pub enum SessionError {
        #[error("The session key has already expired")]
        Expired,

        #[error("No session key found")]
        NotFound,

        #[error("Only the owner or session key granter can perform this operation")]
        NotOwner,

        #[error("This session key wasn't granted to the given grantee")]
        NotGrantee,

        #[error("Must have both id and name specified")]
        InvalidGrantee,

        #[error("Invalid data or indifferent from the grantee")]
        InvalidGranter,

        #[error("Passed a list with no actions. Use AllowedActions::All() if you want to allow all of them")]
        EmptyCreateActions,

        #[error("No actions passed to execute")]
        EmptyPassedActions,

        #[error("Couldn't derivate a String result from given message and method")]
        DerivationError,

        #[error("Invalid actions provided. Check that there are no empty results not dublicates")]
        InvalidActions,

        #[error("Session creation messages aren't allowed to be in allowed message list")]
        InnerSessionAction,

        #[error("Current item cant't be used with the given session key")]
        NotAllowedAction,
    }


    #[cfg(feature = "replay")]
    #[saa_error]
    pub enum ReplayError {
        #[error("{0} is invalid as nonce. Expected: {1}")]
        DifferentNonce(u64, u64),

        #[error("The provided credential was meant for a different chain")]
        ChainIdMismatch,

        #[error("The provided credential was meant for a different contract address")]
        ContractMismatch,

        #[error("Error converting binary to {0}")]
        Convertion(String),
    }



    #[saa_error]
    pub enum StorageError {
        #[error("Error reading {0} from storage: {1}")]
        Read(String, String),

        #[error("Error writing {0} to storage: {1}")]
        Write(String, String),

        #[error("The given credential already exists on this account")]
        AlreadyExists,

        #[error("The given credential was not found on this account")]
        NotFound, 

        #[cfg(feature = "wasm")]
        #[error("Standard error: {0}")]
        Std(#[from] crate::wasm::StdError),

        #[error("Generic error: {0}")]
        Generic(String)
    }




    #[saa_error]
    pub enum AuthError {

        #[error("No credentials provided or credentials are partially missing")]
        NoCredentials,

        #[error("{0}")]
        MissingData(String),

        #[error("Invalid length of {0}.  Expected: {1};  Received: {2}")]
        InvalidLength(String, u16, u16),

        #[error("Values of v other than 27 and 28 not supported. Replay protection (EIP-155) cannot be used here.")]
        RecoveryParam,
        
        #[error("Error recovering from the signature: Addresses do not match")]
        RecoveryMismatch,

        #[error("The signed data is expected to be a replay attach protection envelope")]
        InvalidSignedData,

        #[error("Passkey challenge must be base64url to base64 encoded string")]
        PasskeyChallenge,

        #[error("Unauthorized: {0}")]
        Unauthorized(String),

        #[error("{0}")]
        Signature(String),

        #[error("{0}")]
        Recovery(String),

        #[error("{0}")]
        Generic(String),

        #[error("{0}")]
        Crypto(String),

        #[error("Error converting binary to {0}")]
        Convertation(String),
        
        #[error("Semver parsing error: {0}")]
        SemVer(String),
        
        #[cfg(feature = "replay")]
        #[error("Replay Protection Error: {0}")]
        Replay(#[from] ReplayError),

        #[cfg(feature = "session")]
        #[error("Session Error: {0}")]
        Session(#[from] SessionError),

        #[cfg(feature = "wasm")]
        #[error("{0}")]
        Storage(#[from] StorageError),
    }


    impl From<std::string::FromUtf8Error> for AuthError {
        fn from(err: std::string::FromUtf8Error) -> Self {
            Self::Recovery(err.to_string())
        }
    }


    #[cfg(feature = "wasm")] 
    mod wasm {
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

    #[cfg(feature = "native")] 
    impl From<cosmwasm_crypto::CryptoError> for AuthError {
        fn from(err: cosmwasm_crypto::CryptoError) -> Self {
            Self::Crypto(err.to_string())
        }
    }


}



#[cfg(not(feature = "std"))]
mod no_std_mod {
    use crate::String;
    use saa_schema::{strum_macros, saa_type};

    
    #[cfg(feature = "replay")]
    pub enum ReplayError {
        DifferentNonce(u64, u64),
        ChainIdMismatch,
        ContractMismatch,
    }

    #[cfg(feature = "session")]
    pub enum SessionError {
        Expired,
        InvalidGrantee,
        InvalidGranter,
        EmptyCreateActions,
        EmptyPassedActions,
        DerivationError,
        InvalidActions,
        InnerSessionAction,
        NotAllowedAction,
    }


    #[wasm_serde]
    pub enum AuthError {
        NoCredentials,
        MissingData(String),
        InvalidLength(String, u16, u16),
        RecoveryParam,
        RecoveryMismatch,
        InvalidSignedData,
        PasskeyChallenge,
        Unauthorized(String),
        Signature(String),
        Recovery(String),
        Generic(String),
        Convertation(String),
        Crypto(String),
        SemVer(String),
        #[cfg(feature = "replay")]
        Replay(String),
        #[cfg(feature = "session")]
        Session(String),
    }

    #[cfg(feature = "replay")]
    impl From<ReplayError> for AuthError {
        fn from(err: ReplayError) -> Self {
            Self::Replay(err.to_string())
        }
    }

    #[cfg(feature = "session")]
    impl From<SessionError> for AuthError {
        fn from(err: SessionError) -> Self {
            Self::Session(err.to_string())
        }
    }

}    


#[cfg(feature = "std")]
pub use std_mod::*;


#[cfg(not(feature = "std"))]
pub use no_std_mod::*;





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

