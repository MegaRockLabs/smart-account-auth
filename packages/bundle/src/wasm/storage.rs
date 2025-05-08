use saa_common::{
    from_json, messages::{SignedDataMsg, MsgDataToVerify}, stores::{HAS_NATIVES, VERIFYING_CRED_ID}, wasm::{storage::{self, has_credential}, 
    Api, Env, MessageInfo, Storage
}, AuthError, Verifiable};
use core::str::FromStr;

use crate::{credential::{
    construct_credential, 
    Credential, 
    CredentialName
}, CredentialData};

#[cfg(feature = "replay")]
use saa_common::{
    wasm::storage::increment_account_number,
    messages::MsgDataToSign
};
#[cfg(feature = "iterator")]
pub use {
    saa_common::{CredentialId, CredentialInfo, ensure},
    storage::get_all_credentials, 
    crate::UpdateOperation
};

pub use storage::reset_credentials;

#[cfg(feature = "types")]
pub use saa_common::stores;
#[cfg(feature = "utils")]
pub use storage::{load_count, remove_credential, save_credential, load_credential};



fn credential_from_message(
    storage:   &dyn Storage,
    data_msg:  SignedDataMsg
) -> Result<Credential, AuthError> {
    let initial_id = VERIFYING_CRED_ID.load(storage).unwrap_or_default();

    let id = match data_msg.payload.clone() {
        Some(payload) => {
            if let Some(id) = payload.credential_id {
                id.to_lowercase()
            } else {
                initial_id
            }
        }
        None => {
            initial_id
        }
    };
    let info = storage::load_credential(storage, id.clone())?;

    construct_credential(
        id, 
        CredentialName::from_str(&info.name).unwrap(),
        data_msg.data, 
        data_msg.signature, 
        data_msg.payload.as_ref().map(|p| p.hrp.clone()).unwrap_or(info.hrp),
        info.extension,
        data_msg.payload.map(|p| p.extension).flatten(),
    )
}



pub fn verify_caller(
    storage: &dyn Storage,
    address: &String
) -> Result<(), AuthError> {
    ensure!(has_credential(storage, address), AuthError::Unauthorized(String::from("Unauthorized caller")));
    Ok(())
}


pub fn verify_signed(
    api: &dyn Api,
    storage: &dyn Storage,
    env: &Env,
    msg: SignedDataMsg
) -> Result<(), AuthError> {
    let credential = credential_from_message(storage, msg.clone())?;
    let msgs : MsgDataToVerify = from_json(msg.data)?;
    msgs.validate(storage, env)?;
    credential.verify_cosmwasm(api)?;
    Ok(())
}


#[cfg(feature = "replay")]
pub fn verify_signed_actions<T : serde::de::DeserializeOwned>(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    msg: SignedDataMsg
) -> Result<Vec<T>, AuthError> {
    let credential = credential_from_message(storage, msg.clone())?;
    credential.verify_cosmwasm(api)?;
    increment_account_number(storage)?;
    let msgs : MsgDataToSign<T> = from_json(msg.data)?;
    msgs.validate(storage, env)?;
    Ok(msgs.messages)
}




pub fn save_credentials(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    info: &MessageInfo,
    data: &CredentialData
) -> Result<(), AuthError> {
    data
        .with_native_caller(info)
        .save(api, storage, env)?;
    Ok(())
}


#[cfg(all(feature = "iterator", feature = "replay"))]
pub fn update_credentials_signed(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    info: &MessageInfo,
    msg: SignedDataMsg
) -> Result<(), AuthError> {

    let cred = credential_from_message(storage, msg.clone())?;
    cred.verify_cosmwasm(api)?;

    let sender = info.sender.as_str();
    let to_sign : MsgDataToSign<UpdateOperation> = from_json(msg.data)?;
    let ops = to_sign.messages.clone();

    let mut adds_found = false;

    for op in ops {
        let had_natives = HAS_NATIVES.load(storage)?;
        match op {
            UpdateOperation::Add(data) => {
                adds_found = true;
                data.with_credential(cred.clone()).assert_signed_data(storage, env)?;
                add_credentials(api, storage, data.with_native_caller(sender), had_natives)?;
            },
            UpdateOperation::Remove(idx) => {
                remove_credentials(storage, idx, had_natives)?;
            }
        }
    }
    if !adds_found {
        to_sign.validate(storage, env)?;
        saa_common::wasm::storage::increment_account_number(storage)?;
    }

    Ok(())
}



#[cfg(feature = "iterator")]
pub fn update_credentials(
    api: &dyn Api,
    storage: &mut dyn Storage,
    address: &String,
    op: UpdateOperation,
) -> Result<(), AuthError> {
    let had_natives = HAS_NATIVES.load(storage)?;
    ensure!(had_natives, AuthError::generic("Must supplly signed message to construct a credential"));
    verify_caller( storage, address)?;
    match op {
        UpdateOperation::Add(data) => add_credentials(api, storage, data, had_natives),
        UpdateOperation::Remove(idx) => remove_credentials(storage, idx, had_natives)
    }
}



#[cfg(feature = "iterator")]
fn add_credentials(
    api: &dyn Api,
    storage: &mut dyn Storage,
    data: CredentialData,
    had_natives: bool
) -> Result<(), AuthError> {
    ensure!(!data.credentials.is_empty(), AuthError::generic("Must supply at least one credential to add"));
    
    data.validate()?;
    data.verify_cosmwasm(api)?;

    let mut has_natives = had_natives;

    if let Some(ix) = data.primary_index {
        VERIFYING_CRED_ID.save(storage, &data.credentials[ix as usize].id())?;
    }

    for cred in data.credentials {
        let id = cred.id();
        ensure!(!has_credential(storage, &id), AuthError::AlreadyExists);
        if !has_natives && cred.name() == CredentialName::Native {
            has_natives = true;
        }
        storage::save_credential(storage, &id, &cred.info())?;
    }

    if !had_natives && has_natives {
        HAS_NATIVES.save(storage, &true)?;
    }
    Ok(())
}



#[cfg(feature = "iterator")]
fn remove_credentials(
    storage: &mut dyn Storage,
    idx: Vec<CredentialId>,
    had_natives: bool,
) -> Result<(), AuthError> {
    ensure!(!idx.is_empty(), AuthError::generic("Must supply at least one credential to remove"));

    let all_creds = get_all_credentials(storage)?;
    let left = all_creds.len() - idx.len();
    ensure!(left > 0, AuthError::generic("Must leave at least one credential"));

    let verifying_id = VERIFYING_CRED_ID.load(storage)?;
    let mut native_changed = false;
    let mut verifying_removed = false;

    let remaining : Vec<&(String, CredentialInfo)> = all_creds
        .iter()
        .filter(|(id, info)| {
            if idx.contains(&id) {
                if info.name == CredentialName::Native.to_string() {
                    native_changed = true;
                }
                if *id == verifying_id {
                    verifying_removed = true;
                }
                storage::remove_credential(storage, &id).is_err()
            } else {
                true
            }
        }).collect();
        
    if had_natives && native_changed {
        let still_has = remaining
            .iter()
            .any(|(_, info)| info.name == CredentialName::Native.to_string());
        HAS_NATIVES.save(storage, &still_has)?;
    }

    if verifying_removed {
        let first = remaining.first().unwrap();
        VERIFYING_CRED_ID.save(storage, &first.0)?;
    }

    Ok(())
}


pub fn has_natives(
    storage: &dyn Storage
) -> bool {
    HAS_NATIVES.load(storage).unwrap_or(false)
}

#[cfg(feature = "replay")]
pub fn account_number(
    storage: &dyn Storage
) -> u128 {
    saa_common::stores::ACCOUNT_NUMBER.load(storage).unwrap_or(0)
}