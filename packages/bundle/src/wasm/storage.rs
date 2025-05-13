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
pub(crate) use {
    crate::convert_validate,
    replay::*,
};



use saa_common::{ensure, wasm::{Api, Env, Storage}, AuthError, StorageError};
use crate::{credential::StoredCredentials, msgs::SignedDataMsg, CredentialData};


pub fn verify_caller(
    storage: &dyn Storage,
    address: &String
) -> Result<(), AuthError> {
    ensure!(stores::map_has(storage, &stores::CREDENTIAL_INFOS, address), StorageError::NotFound);
    Ok(())
}


#[cfg(feature = "replay")]
pub fn verify_signed(
    api: &dyn Api,
    storage: &dyn Storage,
    env: &Env,
    msg: SignedDataMsg
) -> Result<(), AuthError> {
    convert_validate(msg.data.as_slice(), env, account_number(storage))?;
    cred_from_signed(api, storage, msg)?;
    Ok(())
} 


#[cfg(not(feature = "replay"))]
pub fn verify_signed(
    api: &dyn Api,
    storage: &dyn Storage,
    msg: SignedDataMsg
) -> Result<(), AuthError> {
    cred_from_signed(api, storage, msg)?;
    Ok(())
}





pub fn get_stored_credentials(
    storage: &dyn Storage
) -> Result<StoredCredentials, AuthError> {

    Ok(StoredCredentials { 
        has_natives: has_natives(storage),
        verifying_id: stores::VERIFYING_ID.load(storage)?,
        #[cfg(feature = "iterator")]
        records: iterator::get_credential_records(storage)?,
        #[cfg(feature = "replay")]
        account_number: account_number(storage), 
        #[cfg(feature = "session")]
        sessions    :   None,
    })
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

    pub use super::{save_credentials, has_natives};

    #[cfg(feature = "types")]
    pub use super::stores;
    
    #[cfg(feature = "utils")]
    pub use super::utils::{cred_from_signed, has_credential};

    #[cfg(feature = "iterator")]
    pub use super::iterator::{update_credentials, reset_credentials};

    #[cfg(all(feature = "iterator", feature="replay"))]
    pub use super::iterator::update_credentials_signed;


    #[cfg(all(feature = "iterator", feature="utils"))]
    pub use super::iterator::{credential_count, get_credential_records};

     #[cfg(all(feature = "replay", feature="utils"))]
    pub use super::replay::increment_account_number;
}


#[cfg(feature = "session")]
pub mod session_methods {
    pub use super::session::handle_actions;

    #[cfg(feature = "utils")]
    pub use super::utils::{session_cred_from_signed, update_session};

    #[cfg(all(feature = "iterator", feature="utils"))]
    pub use super::session::get_session_records;

}



pub mod top_methods {
    pub use super::{verify_caller, verify_signed, get_stored_credentials};
    #[cfg(feature = "replay")]
    pub use super::replay::{verify_signed_actions, account_number};
    #[cfg(feature = "session")]
    pub use super::session::{verify_session_signed, verify_session_native};

}