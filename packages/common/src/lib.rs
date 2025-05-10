#![cfg_attr(not(feature = "std"), no_std)]

mod errors;
mod traits;
mod macros;

pub mod types;
pub mod utils;
pub mod hashes;

pub use errors::*;
pub use traits::*;
pub use types::binary::*;
pub use types::expiration::Expiration;


pub type CredentialId = String;


#[cfg(feature = "native")]
pub mod crypto {pub use cosmwasm_crypto::*;} 



#[cfg(feature = "wasm")]
pub mod wasm;



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


#[cfg(feature = "substrate")]
pub mod substrate {
    pub use ink::env as ink_env;
    pub use {ink_env::Environment as InkEnvironment, ink::EnvAccess as InkApi};
    pub mod default {
        use ink::env as ink_env;
        pub use ink_env::DefaultEnvironment;
        pub type AccountId = <DefaultEnvironment as ink_env::Environment>::AccountId;
        pub type EnvAccess<'a> = ink::EnvAccess<'a, DefaultEnvironment>;
    }
}