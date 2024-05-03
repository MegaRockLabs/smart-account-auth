#![cfg_attr(not(feature = "std"), no_std)]

pub use saa_common::{Verifiable, AuthError, CredentialId, hashes};
pub use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1};
pub use saa_custom::{caller::Caller, cosmos::arbitrary::CosmosArbitrary, evm::EvmCredential};
pub use saa_schema::*;

mod data;
mod wrapper;
mod credential;

pub use credential::*;
pub use wrapper::*;

pub use data::CredentialData;