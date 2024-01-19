use macros_proto;

#[cfg(feature = "cosmwasm")]
pub use {serde, schemars};

#[cfg(feature = "substrate")]
pub use {scale, scale_info};

#[cfg(feature = "solana")]
pub use borsh;

pub use macros_proto::wasm_serde;

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            return Err(core::convert::From::from($e));
        }
    };
}