// Apache license in both but giving the credits to the original authors
// Copied mostly to derive custom traits. Most of the features removed except for +/- operations

// Copied from cosmwasm_std [here](https://github.com/CosmWasm/cosmwasm/tree/main/packages/std)
#[cfg(not(feature = "wasm"))]
pub mod binary;
#[cfg(not(feature = "wasm"))]
pub mod uints;

#[cfg(not(feature = "wasm"))]
mod timestamp;
#[cfg(not(feature = "wasm"))]
pub use timestamp::Timestamp;

#[cfg(feature = "wasm")]
pub use crate::wasm::Timestamp;

// Copied from `cw_utils`  [here](https://github.com/CosmWasm/cw-minus)
pub mod expiration;


pub mod identity;
