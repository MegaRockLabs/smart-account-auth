#[cfg(all(feature = "cosmwasm_1", not(feature = "cosmwasm"), not(feature = "secretwasm")))]
use cosmwasm_std_one as cosmwasm_std;
#[cfg(all(feature = "secretwasm", not(feature = "cosmwasm"), not(feature = "cosmwasm_1")))]
use secretwasm_std as cosmwasm_std;


#[cfg(all(feature = "secretwasm", not(feature = "cosmwasm"), not(feature = "cosmwasm_1")))]
pub use {
    cosmwasm_std::{from_binary as from_json, to_binary as to_json_binary},
    serde_json_wasm::to_string as to_json_string
};

#[cfg(any(feature = "cosmwasm", feature = "cosmwasm_1"))]
pub use cosmwasm_std::{to_json_binary, to_json_string, from_json};


pub use cosmwasm_std::{
    Api, Env, Addr, CanonicalAddr, MessageInfo, Binary, BlockInfo, StdResult, Timestamp,
    StdError, VerificationError, RecoverPubkeyError, CustomMsg, Uint128, Uint64,
    Order, Storage
};
