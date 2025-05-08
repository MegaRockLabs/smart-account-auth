#![cfg_attr(not(feature = "std"), no_std)]


mod data;


mod credential;
mod impls;

pub use saa_schema::wasm_serde;
pub use saa_auth::caller::Caller;
pub use credential::{Credential, CredentialName};
pub use data::{CredentialData, UpdateOperation, UpdateMethod};


#[cfg(feature = "traits")]
mod wrapper;

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
mod wasm;

// the storage restrinction is not needed but there aren't any exports
#[cfg(all(feature = "wasm", feature = "storage"))]
pub use wasm::*;


#[cfg(feature = "session")]
pub use saa_common::sessions;


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

    #[cfg(feature = "passkeys")]
    pub use saa_auth::passkey::utils as passkey;
}


pub use saa_common::{AuthError, CredentialId, CredentialInfo, messages};
