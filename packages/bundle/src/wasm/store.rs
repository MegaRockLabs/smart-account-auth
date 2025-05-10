pub mod stores;
pub mod utils;
#[cfg(feature = "iterator")]
pub mod iterator;
#[cfg(feature = "replay")]
pub mod replay;


pub(crate) use utils::*;
#[cfg(feature = "replay")]
pub(crate) use replay::*;



pub mod storage {
    #[cfg(feature = "replay")]
    pub use super::replay::*;
    
    #[cfg(feature = "iterator")]
    pub use super::iterator::*;
    
    #[cfg(feature = "utils")]
    pub use super::utils::*;
    
    #[cfg(feature = "types")]
    pub use super::stores;
}


use saa_common::{AuthError, Verifiable, wasm::{Api, Env, Storage}, ensure};
use crate::{CredentialData, messages::SignedDataMsg};


pub fn verify_caller(
    storage: &dyn Storage,
    address: &String
) -> Result<(), AuthError> {
    ensure!(utils::has_credential(storage, address), AuthError::Unauthorized(String::from("Unauthorized caller")));
    Ok(())
}


#[cfg(feature = "replay")]
pub fn verify_signed(
    api: &dyn Api,
    storage: &dyn Storage,
    env: &Env,
    msg: SignedDataMsg
) -> Result<(), AuthError> {
    let credential = credential_from_payload(storage, msg.clone())?;
    let msgs : crate::messages::MsgDataToVerify = saa_common::from_json(msg.data)?;
    msgs.validate(storage, env)?;
    credential.verify_cosmwasm(api)?;
    Ok(())
} 


#[cfg(not(feature = "replay"))]
pub fn verify_signed<T : serde::de::DeserializeOwned>(
    api: &dyn Api,
    storage: &dyn Storage,
    msg: SignedDataMsg
) -> Result<T, AuthError> {
    let credential = credential_from_payload(storage, msg.clone())?;
    credential.verify_cosmwasm(api)?;
    let msg = saa_common::from_json(msg.data)?;
    Ok(msg)
}


pub fn save_credentials(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    info: &saa_common::wasm::MessageInfo,
    data: &CredentialData
) -> Result<(), AuthError> {
    data
        .with_native_caller(info)
        .save(api, storage, env)?;
    Ok(())
}



pub fn has_natives(
    storage: &dyn Storage
) -> bool {
    stores::HAS_NATIVES.load(storage).unwrap_or(false)
}