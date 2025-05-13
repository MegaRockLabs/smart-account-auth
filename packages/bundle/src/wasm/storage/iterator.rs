use saa_common::{ensure, wasm::{Api, Storage}, AuthError, CredentialId, StorageError, Verifiable};
use crate::{credential::{CredentialInfo, CredentialName}, CredentialData, CredentialRecord, UpdateOperation};
use super::stores::{
    delete_map_records, get_map_records, 
    map_save, map_remove,
    CREDENTIAL_INFOS, HAS_NATIVES, VERIFYING_ID
};
#[cfg(feature = "replay")]
use {
    saa_common::wasm::{MessageInfo, Env},
    crate::msgs::{MsgDataToSign, SignedDataMsg},
    super::{
        cred_from_signed, 
        replay::account_number,
        stores::ACCOUNT_NUMBER,
    },
};




pub fn get_credential_records(
    storage: &dyn Storage
) -> Result<Vec<CredentialRecord>, StorageError> {
    get_map_records(storage, &CREDENTIAL_INFOS, "credentials")
}



#[cfg(all(feature = "iterator", feature = "utils"))]
pub fn credential_count(storage: &dyn Storage) -> usize {
    super::stores::get_map_count(storage, &CREDENTIAL_INFOS)
}


pub fn reset_credentials(
    storage: &mut dyn Storage,
    #[cfg(feature = "replay")]
    acc_number: bool
) -> Result<(), AuthError> {
    VERIFYING_ID.remove(storage);
    HAS_NATIVES.remove(storage);
    delete_map_records(storage, &CREDENTIAL_INFOS, "credentials")?;
    #[cfg(feature = "replay")]
    if acc_number {
        ACCOUNT_NUMBER.remove(storage);
    }
    Ok(())
}




#[cfg(feature = "replay")]
pub fn update_credentials_signed(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    info: &MessageInfo,
    msg: SignedDataMsg
) -> Result<(), AuthError> {

    let nonce = account_number(storage);
    let signed : MsgDataToSign<UpdateOperation> = crate::convert_validate_return(
        msg.data.as_slice(), env, nonce
    )?;
    let cred = cred_from_signed(api, storage, msg)?;

    for op in signed.messages {
        let had_natives = HAS_NATIVES.load(storage)?;
        match op {
            UpdateOperation::Add(data) => {
                data.with_credential(cred.clone()).validate_replay_all(storage, env)?;
                add_credentials(api, storage, data.with_native_caller(info.sender.as_str()), had_natives)?;
            },
            UpdateOperation::Remove(idx) => {
                remove_credentials(storage, idx, had_natives)?;
            }
        }
    }
    ACCOUNT_NUMBER.save(storage, &(nonce + 1))?;
    Ok(())
}




pub fn update_credentials(
    api: &dyn Api,
    storage: &mut dyn Storage,
    address: &String,
    op: UpdateOperation,
) -> Result<(), AuthError> {
    let had_natives = HAS_NATIVES.load(storage)?;
    ensure!(had_natives, AuthError::generic("Must supplly signed message to construct a credential"));
    super::verify_caller( storage, address)?;
    match op {
        UpdateOperation::Add(data) => add_credentials(api, storage, data, had_natives),
        UpdateOperation::Remove(idx) => remove_credentials(storage, idx, had_natives)
    }
}





fn add_credentials(
    api: &dyn Api,
    storage: &mut dyn Storage,
    data: CredentialData,
    had_natives: bool
) -> Result<(), AuthError> {
    ensure!(!data.credentials.is_empty(), AuthError::NoCredentials);
    
    data.validate()?;
    data.verify_cosmwasm(api)?;

    if let Some(ix) = data.primary_index {
        VERIFYING_ID.save(storage, &data.credentials[ix as usize].id())?;
    }

    let mut has_natives = had_natives;

    for cred in data.credentials {
        let id = cred.id();
        ensure!(!super::stores::map_has(storage, &CREDENTIAL_INFOS, &id), StorageError::AlreadyExists);
        let info = cred.info();
        
        if !has_natives && cred.name() == CredentialName::Native {
            has_natives = true;
        }
        map_save(storage, &CREDENTIAL_INFOS, &id, &info, "new credential")?;
    }

    if !had_natives && has_natives {
        HAS_NATIVES.save(storage, &true)?;
    }
    Ok(())
}



fn remove_credentials(
    storage: &mut dyn Storage,
    idx: Vec<CredentialId>,
    had_natives: bool,
) -> Result<(), AuthError> {
    ensure!(!idx.is_empty(), AuthError::generic("Must supply at least one credential to remove"));

    let all_creds = get_credential_records(storage)?;
    let left = all_creds.len() - idx.len();
    ensure!(left > 0, AuthError::generic("Must leave at least one credential"));

    let verifying_id = VERIFYING_ID.load(storage)?;
    let mut native_changed = false;
    let mut verifying_removed = false;

    let remaining : Vec<&(String, CredentialInfo)> = all_creds
        .iter()
        .filter(|(id, info)| {
            if idx.contains(&id) {
                if info.name == CredentialName::Native {
                    native_changed = true;
                }
                if *id == verifying_id {
                    verifying_removed = true;
                }
                map_remove(storage, &CREDENTIAL_INFOS, id);
                false
            } else {
                true
            }
        }).collect();
        
    if had_natives && native_changed {
        let still_has = remaining
            .iter()
            .any(|(_, info)| info.name == CredentialName::Native);
        HAS_NATIVES.save(storage, &still_has)?;
    }

    if verifying_removed {
        let first = remaining.first().unwrap();
        VERIFYING_ID.save(storage, &first.0)?;
    }

    Ok(())
}

