#![cfg_attr(not(feature = "std"), no_std)]


use saa_schema::wasm_serde;
mod binary;
mod errors;
mod identity;
pub mod utils;
pub mod messages;
pub mod hashes;
pub use errors::*;
pub use binary::{Binary, to_json_binary, from_json};

#[cfg(feature = "storage")]
pub mod storage;


#[cfg(feature = "std")]
pub use std::{
    string::{ToString, String},
    vec, vec::Vec, 
    format
};

#[cfg(not(feature = "std"))]
pub use ink::prelude::{
    string::{ToString, String},
    vec, vec::Vec, 
    format, 
};



#[cfg(feature = "native")]
pub mod crypto {
    pub use cosmwasm_crypto::*;    
} 



#[cfg(feature = "cosmwasm")]
pub mod cosmwasm {
    pub use cosmwasm_std::{
        Api, Env, Addr, CanonicalAddr, MessageInfo, Binary, Storage, Order,
        from_json, to_json_binary, ensure, ensure_eq, ensure_ne
    };
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

#[cfg(feature = "cosmwasm")]
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

    fn info(&self) -> CredentialInfo;

    fn message(&self) -> Binary;

    fn message_digest(&self) -> Result<Vec<u8>, AuthError> {
        Ok(hashes::sha256(&self.message()))
    }

    fn validate(&self) -> Result<(), AuthError>;


    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError>;


    #[cfg(feature = "substrate")]
    fn verify_ink<'a>(&self,  _ : InkApi<'a, impl InkEnvironment>) -> Result<(), AuthError> 
        where Self: Sized 
    {
        #[cfg(feature = "native")]
        if true {
            self.verify()?;
            return Ok(());
        } 
        Err(AuthError::generic("Not implemented"))
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&self,  _:  &dyn Api,  _:  &Env) -> Result<(), AuthError>  
    where Self: Sized {
        #[cfg(feature = "native")]
        if true {
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
