#![cfg_attr(not(feature = "std"), no_std)]

pub use saa_common::{Verifiable, AuthError, CredentialId, Binary, hashes};


pub use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1};
pub use saa_custom::{
    caller::Caller, 
    cosmos::arbitrary::CosmosArbitrary, 
    evm::EvmCredential,
    cosmos::utils as cosmos_utils,
    evm::utils as evm_utils,
    passkey::{PasskeyCredential, ClientData}
};

pub use saa_schema::*;

mod data;
mod wrapper;
mod credential;

pub use credential::*;
pub use wrapper::*;

pub use data::CredentialData;


#[cfg(feature = "native")]
pub use saa_common::crypto;
