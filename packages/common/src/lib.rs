#![cfg_attr(not(feature = "std"), no_std)]

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

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            return Err(core::convert::From::from($e));
        }
    };
}



mod errors;
pub mod hashes;
pub use errors::*;


pub mod crypto {
    pub use cosmwasm_crypto::*;
} 



#[cfg(feature = "cosmwasm")]
pub mod cosmwasm {
    pub use cosmwasm_std::{
        Api, Env, Binary, Addr, CanonicalAddr, MessageInfo,
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


pub type CredentialId = Vec<u8>;


pub trait Verifiable  {

    fn id(&self) -> CredentialId;
    fn validate(&self) -> Result<(), AuthError>;
    fn verify(&self) -> Result<(), AuthError>;


    #[cfg(feature = "substrate")]
    fn verified_ink<'a>(&self,  _ : InkApi<'a, impl InkEnvironment + Clone>) -> Result<Self, AuthError> 
        where Self: Clone
    {
        self.verify()?;
        Ok(self.clone())
    }

    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(& self, _:  &dyn Api, _:  &Env, _: &MessageInfo) -> Result<Self, AuthError> 
        where Self: Clone
    {
        self.verify()?;
        Ok(self.clone())
    }
}


