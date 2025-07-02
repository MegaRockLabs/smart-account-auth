
mod std_mod {
    use saa_schema::saa_error;
    use crate::CredentialName;

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


    #[saa_error]
    pub enum ReplayError {
        #[error("Invalid nonce. Expected: '{0}'")]
        InvalidNonce(u64),

        #[error("The provided credential was meant for a different chain")]
        ChainIdMismatch,

        #[error("The provided credential was meant for a different contract address")]
        AddressMismatch,

        #[error("Invalid messages. Expected to be signing the following inner message: '{0}'")]
        MessageMismatch(String),

        #[error("Error converting from binary to {0}")]
        FromBin(String),

        #[error("Error serializing to binary from: {0}")]
        ToBin(String),

        #[error("Signed too many messages. Expected: {0}; Received: {1}")]
        ManyMessages(u8, u8),

        #[error("Invalid envelope: (chain_id, contract_address, nonce or messages)`. Expected: '{0}'; Received: '{1}'")]
        InvalidEnvelope(String, String),

        #[error("The data for the replay protection is missing or invalid. Item: {0}")]
        MissingData(String),
    }



    #[saa_error]
    pub enum StorageError {
        #[error("Error reading {0} from storage: {1}")]
        Read(String, String),

        #[error("Error writing {0} to storage: {1}")]
        Write(String, String),

        #[error("The given credential already exists on this account. Failed ID: {0}")]
        AlreadyExists(String),

        #[error("The given credential was not found on this account")]
        NotFound, 

        #[cfg(feature = "wasm")]
        #[error("Standard error: {0}")]
        Std(#[from] crate::wasm::StdError),

        #[error("Generic error: {0}")]
        Generic(String)
    }

    #[saa_error]
    pub enum CredentialError {
        #[error("Not provided or partially missing")]
        NoCredentials,

        #[error("At least one credential must be kept for authorization checks")]
        NoneLeft,

        #[error("Too many credentials provided: {0}. Maximum allowed is 255")]
        TooManyCredentials(usize),

        #[error("Invalid primary index: {0}. There are only {1} credentials. (Max index is {1}-1)")]
        IndexOutOfBounds(usize, usize),

        #[error("Client requested to use a native address that called the environment as a credential, but it hasn't been set")]
        NoNativeCaller,

        #[error("One of the main properties of the credential '{0}' are missing")]
        MissingData(CredentialName),

        #[error("Error while processing the credential '{0}', One of the properties is invalid")]
        IncorrectData(CredentialName),

        #[error("The credential '{0}' is not valid. Error in property '{1}': {2}")]
        InvalidProperty(CredentialName, String, String),

        #[error("Passed only (native) credentials that aren't validated by the environment. Need to supply at least one verifyable credential")]
        OnlyCustomNatives,

        #[error("The credential '{0}' was expecting an info object with a property '{1}', however it wasn't provided or was empty")]
        NoInfoProperty(CredentialName, String),

        #[error("The credential '{0}' needs an extended info to be passed. It hasn't been done or there was an error")]
        NoInfoExt(CredentialName),

        #[cfg(feature = "wasm")]
        #[error("(Std) Serialization error: {0}")]
        Std(#[from] crate::wasm::StdError),
    }



    #[saa_error]
    pub enum AuthError {

        #[error("Missing {0}")]
        MissingData(String),

        #[error("Values of v other than 27 and 28 not supported. Replay protection (EIP-155) cannot be used here.")]
        RecoveryParam,
        
        #[error("Error recovering from the signature: Addresses do not match")]
        RecoveryMismatch,

        #[error("Unauthorized: {0}")]
        Unauthorized(String),

        #[error("Invalid length for type '{0}'. Expected: {1}, Received: {2}")]
        InvalidLength(String, u16, u16),

        #[error("Signature verification error for {0} with id of '{1}'")]
        Signature(CredentialName, String),

        #[error("{0}")]
        Recovery(String),

        #[error("{0}")]
        Generic(String),

        #[error("{0}")]
        Crypto(String),

        #[error("Error converting binary to {0}")]
        Convertion(String),

        #[error("Credential: {0}")]
        Credential(#[from] CredentialError),
        
        #[cfg(feature = "replay")]
        #[error("Replay: {0}")]
        Replay(#[from] ReplayError),

        #[cfg(feature = "session")]
        #[error("Session: {0}")]
        Session(#[from] SessionError),

        #[cfg(feature = "wasm")]
        #[error("Storage: {0}")]
        Storage(#[from] StorageError),
    }


    impl From<std::string::FromUtf8Error> for AuthError {
        fn from(err: std::string::FromUtf8Error) -> Self {
            Self::Recovery(err.to_string())
        }
    }


    #[cfg(feature = "eth_typed_data")] 
    impl From<serde_json::DeserializerError> for AuthError {
        fn from(err: serde_json::DeserializerError) -> Self {
            Self::Generic(err.to_string())
        }
    }


    #[cfg(feature = "wasm")] 
    mod wasm {
        use super::AuthError;

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
    use saa_schema::{saa_error, saa_type, strum_macros};

    
    #[cfg(feature = "replay")]
    pub enum ReplayError {
        DifferentNonce(u64, u64),
        ChainIdMismatch,
        AddressMismatch,
        MessageMismatch(String),
        FromBin(String),
        ToBin(String),
        ManyMessages(u8, u8),
        InvalidEnvelope(String, String),
        MissingData(String),
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


    #[saa_error]
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

