use saa_common::{wasm::{Api, Env, Storage}, AuthError};
use crate::{messages::utils::convert_validate_return, msgs::SignedDataMsg};
use super::stores::ACCOUNT_NUMBER;
use super::utils::cred_from_signed;


pub fn account_number(
    storage: &dyn Storage
) -> u64 {
    ACCOUNT_NUMBER.load(storage).unwrap_or(0)
}



#[cfg(feature = "utils")]
pub fn increment_account_number(
    storage: &mut dyn Storage
) -> Result<(), saa_common::StorageError> {
    if super::stores::item_exist(storage, &ACCOUNT_NUMBER) {
        ACCOUNT_NUMBER.save(storage, &1u64)
        .map_err(|e| saa_common::StorageError::Write(
            "initial account number".to_string(), 
            e.to_string()
        ))?;
    } else {
        ACCOUNT_NUMBER.update(storage, |n| 
            Ok::<u64, saa_common::wasm::StdError>(n + 1)
        )
        .map_err(|e| saa_common::StorageError::Write(
            "updated account number".to_string(), 
            e.to_string()
        ))?;
    }
    Ok(())
}



pub fn verify_signed_actions<T : serde::de::DeserializeOwned>(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    msg: SignedDataMsg
) -> Result<Vec<T>, AuthError> {
    let nonce = account_number(storage);
    let signed = convert_validate_return(msg.data.as_slice(), env, nonce)?;
    cred_from_signed(api, storage, msg)?;
    ACCOUNT_NUMBER.save(storage, &(nonce + 1))?;
    Ok(signed.messages)
}


