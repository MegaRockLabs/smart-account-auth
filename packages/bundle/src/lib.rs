#![cfg_attr(not(feature = "std"), no_std)]

pub use saa_common::{Verifiable, AuthError, CredentialId, Binary, hashes};
pub use saa_custom::caller::Caller;

#[cfg(feature = "curves")]
pub use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1, secp256r1::Secp256r1};

#[cfg(feature = "passkeys")]
pub use saa_custom::passkey::{PasskeyCredential, ClientData};

#[cfg(feature = "ethereum")]
pub use saa_custom::eth::{EthPersonalSign, utils as eth_utils};

#[cfg(feature = "cosmos")]
pub use saa_custom::cosmos::{arbitrary::CosmosArbitrary, utils as cosmos_utils};


pub use saa_schema::*;

mod data;
mod wrapper;
mod credential;

pub use credential::{Credential, Credentials};
pub use wrapper::CredentialsWrapper;
pub use data::CredentialData;

#[cfg(feature = "native")]
pub use saa_common::crypto;
