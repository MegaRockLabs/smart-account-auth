#![cfg_attr(not(feature = "std"), no_std)]

mod errors;
mod traits;
mod macros;
mod credential;

pub use errors::*;
pub use traits::*;
pub use credential::*;

pub mod types;
pub mod utils;
pub mod messages;
pub mod hashes;


#[cfg(feature = "storage")]
pub mod stores;

#[cfg(feature = "session")]
pub mod sessions;

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



#[cfg(not(feature = "wasm"))]
pub use types::binary::{Binary, to_json_binary, from_json};

#[cfg(feature = "wasm")]
pub use wasm::{Binary, to_json_binary, from_json};

