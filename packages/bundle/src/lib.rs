pub use saa_common::{Verifiable, AuthError, CredentialId};
pub use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1};
pub use saa_custom::{caller::Caller, cosmos::arbitrary::CosmosArbitrary, evm::EvmCredential};
pub use saa_schema::*;


mod data;
mod data_ink;
mod wrapper;
mod credential;

pub use credential::*;
pub use wrapper::*;



#[cfg(not(feature = "substrate"))]
pub use data::CredentialData;

#[cfg(feature = "substrate")]
pub use data_ink::CredentialData;