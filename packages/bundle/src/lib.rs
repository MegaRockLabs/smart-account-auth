#![cfg_attr(not(feature = "std"), no_std)]


mod data;
mod wasm;
mod wrapper;
mod credential;

pub use saa_schema::wasm_serde;
pub use saa_auth::caller::Caller;
pub use credential::Credential;
pub use data::{CredentialData, UpdateOperation};


#[cfg(feature = "passkeys")]
pub use saa_auth::passkey::PasskeyCredential;
#[cfg(feature = "ethereum")]
pub use saa_auth::eth::EthPersonalSign;
#[cfg(feature = "cosmos")]
pub use saa_auth::cosmos::CosmosArbitrary;

#[cfg(feature = "curves")]
pub use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1, secp256r1::Secp256r1};
#[cfg(all(not(feature = "curves"), feature = "ed25519" ))]
pub use saa_curves::ed25519::Ed25519;

#[cfg(feature = "native")]
pub use saa_common::crypto;


#[cfg(feature = "wasm")]
pub use wasm::*;


#[cfg(feature = "traits")]
pub use {wrapper::CredentialsWrapper, saa_common::Verifiable};


#[cfg(feature = "types")]
pub mod types {
    pub use saa_common::types::*;

    #[cfg(feature = "passkeys")]
    pub use saa_auth::passkey::ClientData;
}


#[cfg(feature = "utils")]
pub mod utils {
    pub use saa_common::hashes;
    pub use saa_common::utils::*;
    
    #[cfg(feature = "cosmos")]
    pub use saa_auth::cosmos::utils as cosmos;

    #[cfg(feature = "ethereum")]
    pub use saa_auth::eth::utils as eth;
}


pub use saa_common::{AuthError, CredentialId, CredentialName, CredentialInfo, messages};
