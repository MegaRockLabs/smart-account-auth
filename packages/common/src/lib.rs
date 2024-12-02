#![cfg_attr(not(feature = "std"), no_std)]

use saa_schema::wasm_serde;
mod binary;
mod errors;
pub mod utils;
pub mod messages;
pub mod hashes;
pub use errors::*;
pub use binary::{Binary, to_json_binary, from_json};


#[cfg(all(not(feature = "cosmwasm_2_0"), not(feature = "native")))]
mod identity;

#[cfg(feature = "storage")]
pub mod storage;


#[cfg(any(feature = "std", not(feature = "substrate")))]
pub use std::{
    string::{ToString, String},
    vec, vec::Vec, 
    format
};

#[cfg(all(not(feature = "std"), feature = "substrate"))]
pub use ink::prelude::{
    string::{ToString, String},
    vec, vec::Vec, 
    format, 
};

#[cfg(feature = "native")]
pub mod crypto {
    pub use cosmwasm_crypto::*;  
} 


#[cfg(all(feature = "cosmwasm", not(feature = "secretwasm")))]
pub mod cosmwasm {
    pub use cosmwasm_std::{
        Api, Env, Addr, CanonicalAddr, MessageInfo, Binary,
        from_json, to_json_binary, CustomMsg,
        StdError, VerificationError, RecoverPubkeyError
    };
    #[cfg(feature = "storage")]
    pub use cosmwasm_std::Storage;
    #[cfg(feature = "iterator")]
    pub use cosmwasm_std::Order;
}


#[cfg(feature = "secretwasm")]
pub mod cosmwasm {
    pub use secretwasm_std::{
        Api, Env, Addr, CanonicalAddr, MessageInfo, Binary,
        from_binary as from_json, to_binary as to_json_binary,
        StdError, VerificationError, RecoverPubkeyError,
        CustomMsg
    };
    #[cfg(feature = "storage")]
    pub use secretwasm_std::Storage;
    #[cfg(feature = "iterator")]
    pub use secretwasm_std::Order;
}




#[cfg(feature = "substrate")]
pub mod substrate {
    pub use ink::env as ink_env;
    pub use {
        ink_env::Environment as InkEnvironment,
        ink::EnvAccess as InkApi,
    };

    pub mod default {
        use ink::env as ink_env;
        pub use ink_env::DefaultEnvironment;
        pub type AccountId = <DefaultEnvironment as ink_env::Environment>::AccountId;
        pub type EnvAccess<'a> = ink::EnvAccess<'a, DefaultEnvironment>;
    }
}

#[cfg(feature = "wasm")]
use cosmwasm::*;
#[cfg(feature = "substrate")]
use substrate::*;


#[macro_export]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            return Err(core::convert::From::from($e));
        }
    };
}



pub trait Verifiable  {

    fn id(&self) -> CredentialId;

    fn hrp(&self) -> Option<String> {
        None
    }

    fn validate(&self) -> Result<(), AuthError>;

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError>;


    #[cfg(feature = "substrate")]
    fn verify_ink<'a>(&self,  _ : InkApi<'a, impl InkEnvironment>) -> Result<(), AuthError> 
        where Self: Sized 
    {
        #[cfg(feature = "native")]
        {
            self.verify()?;
            return Ok(());
        } 
        Err(AuthError::generic("Not implemented"))
    }


    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self,  _:  &dyn Api) -> Result<(), AuthError>  
        where Self: Sized 
    {
        #[cfg(feature = "native")]
        {
            self.verify()?;
            return Ok(());
        } 
        Err(AuthError::generic("Not implemented"))
    }

}


#[wasm_serde]
pub struct CredentialInfo {
    /// name of the used credential
    pub name: CredentialName,
    /// human readable prefix to encode from a public key
    pub hrp: Option<String>,
    /// extension data
    pub extension: Option<Binary>,
}


#[wasm_serde]
pub enum CredentialName {
    Caller,
    CosmosArbitrary,
    EthPersonalSign,
    Passkey,
    Secp256k1,
    Secp256r1,
    Ed25519,
}


pub type CredentialId = Vec<u8>;
