#![cfg_attr(not(feature = "std"), no_std)]

use saa_macros_proto;

pub use saa_macros_proto::{wasm_serde, wasm_string_struct};


pub use serde;

#[cfg(feature = "cosmwasm")]
pub use schemars;

#[cfg(feature = "solana")]
pub use borsh;

#[cfg(feature = "substrate")]
pub use scale;

#[cfg(all(feature = "std", feature = "substrate"))]
pub use scale_info;
