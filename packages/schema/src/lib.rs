#![cfg_attr(not(feature = "std"), no_std)]

pub use strum;
pub use strum_macros; 
pub use thiserror;
pub use saa_proto_core::saa_error;


#[cfg(feature = "cosmwasm")]
pub use cw_schema::Schemaifier;
#[cfg(feature = "wasm")]
pub use {serde, cosmwasm_schema::schemars, cosmwasm_schema::{QueryResponses}};
#[cfg(feature = "solana")]
pub use borsh;
#[cfg(feature = "substrate")]
pub use scale;
#[cfg(all(feature = "std", feature = "substrate"))]
pub use scale_info;


#[cfg(all(
    not(feature = "wasm"), 
    not(feature = "solana"), 
    not(feature = "substrate"))
)]
pub use saa_proto_core::saa_type;
#[cfg(all(
    feature = "solana", 
    not(feature = "wasm"), 
    not(feature = "substrate"))
)]
pub use {borsh, saa_proto_solana::saa_type};
#[cfg(all(
    feature = "substrate", 
    not(feature = "wasm"), 
    not(feature = "solana"))
)]
pub use {saa_proto_substrate::saa_type, scale};
#[cfg(not(feature = "wasm"))]
pub use saa_proto_core::{saa_derivable, saa_str_struct};
#[cfg(feature = "wasm")]
#[cfg(all(feature = "wasm", not(feature = "cosmwasm")))]
pub use saa_proto_wasm::{saa_type, saa_derivable, saa_str_struct};
#[cfg(feature = "cosmwasm")]
pub use saa_proto_cosmwasm::{saa_type, saa_derivable, saa_str_struct};

