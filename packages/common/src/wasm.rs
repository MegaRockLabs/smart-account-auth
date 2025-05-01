mod messages;

#[cfg(feature = "storage")]
pub mod storage;


#[cfg(feature = "cosmwasm")]
pub mod module {
    pub use cosmwasm_std::{
        Api, Env, Addr, CanonicalAddr, MessageInfo, Binary, BlockInfo,
        from_json, to_json_binary, CustomMsg, StdResult,
        StdError, VerificationError, RecoverPubkeyError
    };
    #[cfg(feature = "storage")]
    pub use cosmwasm_std::Storage;
    #[cfg(feature = "iterator")]
    pub use cosmwasm_std::Order;
}


#[cfg(all(feature = "secretwasm", not(feature = "cosmwasm")))]
pub mod module {
    pub use secretwasm_std::{
        Api, Env, Addr, CanonicalAddr, MessageInfo, Binary, BlockInfo,
        from_binary as from_json, to_binary as to_json_binary, StdResult,
        StdError, VerificationError, RecoverPubkeyError,
        CustomMsg
    };
    #[cfg(feature = "storage")]
    pub use secretwasm_std::Storage;
    #[cfg(feature = "iterator")]
    pub use secretwasm_std::Order;
}


pub use module::*;