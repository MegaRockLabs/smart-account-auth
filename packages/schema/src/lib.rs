#![cfg_attr(not(feature = "std"), no_std)]

use saa_macros_proto;
pub use serde;

pub use saa_macros_proto::{wasm_serde, wasm_string_struct};

#[cfg(feature = "session")]
pub use {
    strum, strum_macros,
    saa_macros_proto::{session_action, session_query}
};


#[cfg(feature = "cosmwasm")]
pub use schemars;

#[cfg(feature = "solana")]
pub use borsh;

#[cfg(feature = "substrate")]
pub use scale;

#[cfg(all(feature = "std", feature = "substrate"))]
pub use scale_info;
