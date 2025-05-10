use saa_common::{from_json, wasm::{Api, Env, Storage}, AuthError};
use crate::messages::{MsgDataToSign, SignedDataMsg};
use super::stores::ACCOUNT_NUMBER;
use super::utils::credential_from_payload;


pub fn account_number(
    storage: &dyn Storage
) -> u128 {
    ACCOUNT_NUMBER.load(storage).unwrap_or(0)
}




pub fn verify_signed_actions<T : serde::de::DeserializeOwned>(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    msg: SignedDataMsg
) -> Result<Vec<T>, AuthError> {
    let credential = credential_from_payload(storage, msg.clone())?;
    credential.verify_cosmwasm(api)?;
    increment_account_number(storage)?;
    let msgs : MsgDataToSign<T> = from_json(msg.data)?;
    msgs.validate(storage, env)?;
    Ok(msgs.messages)
}



pub fn increment_account_number(
    storage: &mut dyn Storage
) -> Result<(), AuthError> {
    #[cfg(feature = "cwasm")]

    #[cfg(feature = "cwasm")]
    if !ACCOUNT_NUMBER.exists(storage) {
        ACCOUNT_NUMBER.save(storage, &1u128)?;
    } else {
        ACCOUNT_NUMBER.update(storage, |n| 
            Ok::<u128, saa_common::wasm::StdError>(n + 1)
        )?;
    }
    #[cfg(all(feature = "secretwasm", not(feature = "cwasm")))]
    if ACCOUNT_NUMBER.is_empty(storage) {
        ACCOUNT_NUMBER.save(storage, &1u128)?;
    } else {
        ACCOUNT_NUMBER.update(storage, |n| Ok::<u128, crate::wasm::StdError>(n + 1))?;
    }
    Ok(())
}

