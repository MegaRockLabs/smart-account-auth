#![cfg_attr(not(feature = "std"), no_std)]

use saa_proto_core;
pub use saa_proto_core::saa_error;


#[cfg(not(feature = "cosmwasm"))]
use saa_proto_core::{saa_type, saa_derivable};


#[cfg(feature = "cosmwasm")]
use saa_proto_wasm;

#[cfg(feature = "cosmwasm")]
pub use {
    saa_proto_wasm::{saa_type, saa_derivable},
    cosmwasm_schema::{QueryResponses},
    schemars, 
};


pub use strum;
pub use strum_macros; 
pub use serde;
pub use thiserror;
pub use thiserror::Error;
#[cfg(feature = "solana")]
pub use borsh;
#[cfg(feature = "substrate")]
pub use scale;
#[cfg(all(feature = "std", feature = "substrate"))]
pub use scale_info;
