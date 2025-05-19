// Apache license in both but giving the credits to the original authors
// Copied to derive custom traits. Most of the features removed except for +/- operations

use saa_schema::{saa_type};

// Copied from `cosmwasm_crypto` [here](https://github.com/CosmWasm/cosmwasm/tree/main/packages/crypto)
pub mod identity;
// Copied from `cw_utils`  [here](https://github.com/CosmWasm/cw-minus)
pub mod expiration;

// Copied from cosmwasm_std [here](https://github.com/CosmWasm/cosmwasm/tree/main/packages/std)
#[cfg(not(feature = "wasm"))]
mod ts;
#[cfg(not(feature = "wasm"))]
mod bin;
#[cfg(not(feature = "wasm"))]
mod uint;


pub mod binary {
    #[cfg(not(feature = "wasm"))]
    pub use super::bin::{Binary, to_json_binary, from_json};
    #[cfg(feature = "wasm")]
    pub use crate::wasm::{Binary, to_json_binary, from_json, to_json_string};
    #[cfg(all(feature = "types", not(feature = "wasm")))]
    pub use serde_json_wasm::to_string as to_json_string;
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


#[saa_type]
pub struct Empty {}

#[cfg(feature = "session")]
impl saa_schema::strum::IntoDiscriminant for Empty {
    type Discriminant = String;
    fn discriminant(&self) -> Self::Discriminant {
        String::from("empty")
    }
}

impl core::fmt::Display for Empty {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "empty")
    }
}