#![cfg_attr(not(feature = "std"), no_std)]
mod traits;
mod macros;
mod env;

pub mod types;
pub use env::*;
pub use types::errors::*;
pub use types::binary::*;
pub use types::uints::Uint64;
pub use types::exp::Expiration;
pub use traits::Verifiable;

pub type CredentialId = String;