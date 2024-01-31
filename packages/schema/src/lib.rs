#![cfg_attr(all(feature = "substrate", not(feature = "std")), no_std)]

use macros_proto;

pub use macros_proto::wasm_serde;

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            return Err(core::convert::From::from($e));
        }
    };
}


#[cfg(feature = "cosmwasm")]
pub use {serde, schemars};

#[cfg(feature = "solana")]
pub use borsh;

#[cfg(feature = "substrate")]
pub use scale;

#[cfg(feature = "std")]
pub use scale_info;
