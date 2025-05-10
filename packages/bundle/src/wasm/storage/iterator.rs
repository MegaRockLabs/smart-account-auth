use saa_common::{CredentialId, AuthError, Verifiable, ensure, wasm::{Api, Storage}};
use crate::{credential::{CredentialName, CredentialInfo}, CredentialData, UpdateOperation};
use super::stores::{CREDENTIAL_INFOS, VERIFYING_CRED_ID, HAS_NATIVES};



pub fn get_all_cred_infos(
    storage: &dyn Storage
) -> Result<Vec<(CredentialId, CredentialInfo)>, AuthError> {
    let credentials = CREDENTIAL_INFOS
    .range(storage, None, None, saa_common::wasm::Order::Ascending)
    .collect::<Result<Vec<(CredentialId, CredentialInfo)>, saa_common::wasm::StdError>>()?;
    Ok(credentials)
}



#[cfg(all(feature = "secretwasm", not(feature = "cwasm")))]
pub fn get_all_cred_infos(
    storage: &dyn Storage
) -> Result<Vec<(CredentialId, CredentialInfo)>, AuthError> {
    let credentials = CREDENTIAL_INFOS
        .iter(storage)?
        .collect::<Result<Vec<(CredentialId, CredentialInfo)>, saa_common::wasm::StdError>>()?;
    Ok(credentials)
}


pub fn load_count(storage: &dyn Storage) -> usize {
    #[cfg(all(feature = "secretwasm", not(feature = "cwasm")))]
    return CREDENTIAL_INFOS.get_len(storage).unwrap_or(0) as usize;
    #[cfg(feature = "cwasm")]
    CREDENTIAL_INFOS.keys(storage, None, None, saa_common::wasm::Order::Ascending).count()
}


pub fn reset_credentials(
    storage: &mut dyn Storage,
    #[cfg(feature = "replay")]
    acc_number: bool
) -> Result<(), AuthError> {
    VERIFYING_CRED_ID.remove(storage);
    HAS_NATIVES.remove(storage);
    #[cfg(all(feature = "secretwasm", not(feature = "cwasm")))]
    {
        let keys : Vec<CredentialId> = CREDENTIAL_INFOS
            .iter_keys(storage)?.map(|k| k.unwrap()).collect();

        for key in keys {
            CREDENTIAL_INFOS.remove(storage, &key)?;
        }
    }
    #[cfg(feature = "cwasm")]
    CREDENTIAL_INFOS.clear(storage);
    #[cfg(feature = "replay")]
    if acc_number {
        super::stores::ACCOUNT_NUMBER.remove(storage);
    }
    Ok(())
}




#[cfg(feature = "replay")]
pub fn update_credentials_signed(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &saa_common::wasm::Env,
    info: &saa_common::wasm::MessageInfo,
    msg: crate::messages::SignedDataMsg
) -> Result<(), AuthError> {

    let cred = super::credential_from_payload(storage, msg.clone())?;
    cred.verify_cosmwasm(api)?;

    let sender = info.sender.as_str();
    let to_sign : crate::messages::MsgDataToSign<UpdateOperation> = saa_common::from_json(msg.data)?;
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
        super::replay::increment_account_number(storage)?;
    }

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
    ensure!(!data.credentials.is_empty(), AuthError::generic("Must supply at least one credential to add"));
    
    data.validate()?;
    data.verify_cosmwasm(api)?;

    let mut has_natives = had_natives;

    if let Some(ix) = data.primary_index {
        VERIFYING_CRED_ID.save(storage, &data.credentials[ix as usize].id())?;
    }

    for cred in data.credentials {
        let id = cred.id();
        ensure!(!super::has_credential(storage, &id), AuthError::AlreadyExists);
        if !has_natives && cred.name() == CredentialName::Native {
            has_natives = true;
        }
        super::utils::save_credential(storage, &id, &cred.info())?;
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

    let all_creds = get_all_cred_infos(storage)?;
    let left = all_creds.len() - idx.len();
    ensure!(left > 0, AuthError::generic("Must leave at least one credential"));

    let verifying_id = VERIFYING_CRED_ID.load(storage)?;
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
                super::utils::remove_credential(storage, &id).is_err()
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
        VERIFYING_CRED_ID.save(storage, &first.0)?;
    }

    Ok(())
}

