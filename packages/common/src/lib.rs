#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(not(feature = "wasm"), not(feature = "native"), not(feature = "substrate"), not(feature = "solana")))]
compile_error!("at least one of the supported envieronments must be enabled: cosmwasm, cosmwasm_v1, secretwasm, native, substrate, or solana");

mod traits;
mod macros;
mod env;

pub mod types;
pub use env::*;
pub use types::cred::*;
pub use types::errors::*;
pub use types::binary::*;
pub use types::uints::Uint64;
pub use types::exp::Expiration;
pub use traits::{Verifiable, Identifiable};
pub use types::exts::{InfoExtension, PayloadExtension};
#[cfg(feature = "replay")]
pub use types::signed::{MsgDataToSign, MsgDataToVerify};