#![cfg_attr(not(feature = "std"), no_std)]

pub use saa_common::{
    Verifiable, AuthError, Binary, to_json_binary, from_json,
    CredentialId, CredentialName, CredentialInfo,
    hashes, utils, messages, 
};

#[cfg(all(feature = "cosmwasm", feature = "storage"))]
pub use saa_common::storage;
pub use saa_custom::caller::Caller;
pub use saa_schema::wasm_serde;

mod data;
mod wrapper;
mod functions;
mod credential;

pub use data::{CredentialData, UpdateOperation};
pub use wrapper::CredentialsWrapper;
pub use credential::*;

#[cfg(all(feature = "wasm", feature = "storage"))]
pub use functions::*;


#[cfg(feature = "curves")]
pub use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1, secp256r1::Secp256r1};

#[cfg(all(not(feature = "curves"), feature = "ed25519" ))]
pub use saa_curves::ed25519::Ed25519;

#[cfg(feature = "passkeys")]
pub use saa_custom::passkey::{PasskeyCredential, ClientData};

#[cfg(feature = "ethereum")]
pub use saa_custom::eth::{EthPersonalSign, utils as eth_utils};

#[cfg(feature = "cosmos")]
pub use saa_custom::cosmos::{CosmosArbitrary, utils as cosmos_utils};

#[cfg(feature = "native")]
pub use saa_common::crypto;
