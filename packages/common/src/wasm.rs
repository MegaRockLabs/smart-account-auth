#[cfg(feature = "replay")]
mod messages;

#[cfg(feature = "storage")]
pub mod storage;


#[cfg(feature = "cwasm")]
pub mod module {
    #[cfg(all(feature = "cosmwasm_1", not(feature = "cosmwasm")))]
    use cosmwasm_std_one as cosmwasm_std;

    pub use cosmwasm_std::{
        Api, Env, Addr, CanonicalAddr, MessageInfo, Binary, BlockInfo,
        from_json, to_json_binary, StdResult, Timestamp,
        StdError, VerificationError, RecoverPubkeyError,
        CustomMsg
    };
    #[cfg(feature = "storage")]
    pub use cosmwasm_std::Storage;
    #[cfg(feature = "iterator")]
    pub use cosmwasm_std::Order;
}


#[cfg(all(feature = "secretwasm", not(feature = "cwasm")))]
pub mod module {
    pub use secretwasm_std::{
        Api, Env, Addr, CanonicalAddr, MessageInfo, Binary, BlockInfo, Empty,
        from_binary as from_json, to_binary as to_json_binary, StdResult,
        StdError, VerificationError, RecoverPubkeyError, Timestamp,
        CustomMsg
    };
    #[cfg(feature = "storage")]
    pub use secretwasm_std::Storage;
    #[cfg(feature = "iterator")]
    pub use secretwasm_std::Order;
}


pub use module::*;