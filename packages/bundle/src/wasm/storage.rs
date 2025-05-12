pub mod stores;
pub mod utils;
#[cfg(feature = "iterator")]
pub mod iterator;
#[cfg(feature = "replay")]
pub mod replay;
#[cfg(all(feature = "session", feature="cwasm"))]
pub mod session;


pub(crate) use utils::*;
#[cfg(feature = "replay")]
pub(crate) use replay::*;



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
    let data = msg.data.to_vec();
    let credential = credential_from_payload(storage, msg)?;
    let msgs : crate::messages::MsgDataToVerify = saa_common::from_json(data)?;
    msgs.validate(storage, env)?;
    credential.verify_cosmwasm(api)?;
    Ok(())
} 


#[cfg(not(feature = "replay"))]
pub fn verify_signed(
    api: &dyn Api,
    storage: &dyn Storage,
    msg: SignedDataMsg
) -> Result<(), AuthError> {
    let credential = credential_from_payload(storage, msg)?;
    credential.verify_cosmwasm(api)?;
    Ok(())
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






pub mod storage_methods {
    #[cfg(feature = "replay")]
    pub use super::replay::*;
    
    #[cfg(feature = "iterator")]
    pub use super::iterator::*;
    
    #[cfg(feature = "utils")]
    pub use super::utils::*;

    #[cfg(feature = "types")]
    pub use super::stores;

    #[cfg(all(feature = "session", feature="cwasm"))]
    pub use super::session;
}



pub mod top_methods {
    pub use super::{verify_caller, verify_signed, save_credentials, has_natives};
    #[cfg(feature = "replay")]
    pub use super::replay::verify_signed_actions;
}