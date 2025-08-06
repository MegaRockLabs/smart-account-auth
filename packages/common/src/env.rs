#[cfg(feature = "wasm")]
pub mod wasm {
    #[cfg(all(not(feature = "cosmwasm_v1"), not(feature = "cosmwasm"), not(feature = "secretwasm")))]
    compile_error!("can't specify `wasm` feature directly, use one of `cosmwasm`, `cosmwasm_v1` or `secretwasm` instead");
    
    #[cfg(all(feature = "cosmwasm_v1", not(feature = "cosmwasm"), not(feature = "secretwasm")))]
    use cosmwasm_std_v1 as cosmwasm_std;
    #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm"), not(feature = "cosmwasm_v1")))]
    use secretwasm_std as cosmwasm_std;
    
    #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm"), not(feature = "cosmwasm_v1")))]
    pub use {
        cosmwasm_std::{from_binary as from_json, to_binary as to_json_binary},
        serde_json_wasm::to_string as to_json_string
    };
    pub use cosmwasm_std::*;

    
    pub fn get_contract_info(
        store: &dyn Storage
    ) -> Result<crate::types::ContractVersion, crate::AuthError> {
        store
        .get(b"contract_info")
        .ok_or_else(|| {
            crate::AuthError::Storage(crate::StorageError::Read(
                "contract_info".to_string(),
                "cw2::set_contract_version() hasn't been called".to_string(),
            ))
        })
        .and_then(|raw| {
            from_json(&raw).map_err(|e| {
                crate::AuthError::Storage(crate::StorageError::Read(
                    "contract_info".to_string(),
                    e.to_string(),
                ))
            })
        })
    }
}


#[cfg(feature = "substrate")]
pub mod substrate {
    pub use ink::env as ink_env;
    pub use {ink_env::Environment as InkEnvironment, ink::EnvAccess as InkApi};
    pub mod default {
        use ink::env as ink_env;
        pub use ink_env::DefaultEnvironment;
        pub type AccountId = <DefaultEnvironment as ink_env::Environment>::AccountId;
        pub type EnvAccess<'a> = ink::EnvAccess<'a, DefaultEnvironment>;
    }
}

#[cfg(any(feature = "std", not(feature = "substrate")))]
pub use {core::str::FromStr, std::{string::{ToString, String}, vec, vec::Vec, format}};
#[cfg(all(not(feature = "std"), feature = "substrate"))]
pub use ink::prelude::{string::{String, ToString, FromStr}, vec, vec::Vec, format};