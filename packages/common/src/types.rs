pub mod msgs;
pub mod errors;

// Apache license in both but giving the credits to the original authors
// Copied to derive custom traits. Most of the features removed except for +/- operations

// Copied from `cw_utils`  [here](https://github.com/CosmWasm/cw-minus)
pub mod exp;

// Copied from cosmwasm_std [here](https://github.com/CosmWasm/cosmwasm/tree/main/packages/std)
#[cfg(not(feature = "wasm"))]
mod ts;
#[cfg(not(feature = "wasm"))]
mod bin;
#[cfg(not(feature = "wasm"))]
mod uint;



pub mod binary {
    #[cfg(not(feature = "wasm"))]
    pub use super::bin::{Binary, to_json_binary, from_json, to_json_string};
    #[cfg(feature = "wasm")]
    pub use crate::wasm::{Binary, to_json_binary, from_json, to_json_string};
}

pub mod uints {
    #[cfg(not(feature = "wasm"))]
    pub use super::uint::{Uint128, Uint64};
    #[cfg(feature = "wasm")]
    pub use crate::wasm::{Uint128, Uint64};
}

pub mod timestamp {
    #[cfg(not(feature = "wasm"))]
    pub use super::ts::Timestamp;
    #[cfg(feature = "wasm")]
    pub use crate::wasm::Timestamp;
}