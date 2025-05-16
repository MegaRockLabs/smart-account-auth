#![cfg_attr(not(feature = "std"), no_std)]

pub use strum;
pub use strum_macros; 
pub use thiserror;
pub use saa_proto_core::saa_error;


#[cfg(feature = "cosmwasm")]
pub use {serde, schemars, cosmwasm_schema::{QueryResponses}};
#[cfg(feature = "solana")]
pub use borsh;
#[cfg(feature = "substrate")]
pub use scale;
#[cfg(all(feature = "std", feature = "substrate"))]
pub use scale_info;


#[cfg(all(
    not(feature = "cosmwasm"), 
    not(feature = "solana"), 
    not(feature = "substrate"))
)]
pub use saa_proto_core::{saa_type};
#[cfg(all(
    feature = "solana", 
    not(feature = "cosmwasm"), 
    not(feature = "substrate"))
)]
pub use {borsh, saa_proto_solana::{saa_type}};
#[cfg(all(
    feature = "substrate", 
    not(feature = "cosmwasm"), 
    not(feature = "solana"))
)]
pub use {scale, saa_proto_substrate::{saa_type}};
#[cfg(not(feature = "cosmwasm"))]
pub use saa_proto_core::{saa_derivable};
#[cfg(feature = "cosmwasm")]
pub use {saa_proto_wasm::{saa_type, saa_derivable}};

