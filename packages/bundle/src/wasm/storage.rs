use saa_common::{
    ensure, messages::SignedDataMsg, stores::{HAS_NATIVES, VERIFYING_CRED_ID}, wasm::{storage::{self, has_credential}, 
    Api, Env, MessageInfo, Storage
}, AuthError, CredentialId, CredentialInfo, Verifiable};
use core::str::FromStr;

use crate::{credential::{
    construct_credential, 
    Credential, 
    CredentialName
}, CredentialData, UpdateOperation};

pub use storage::reset_credentials;

#[cfg(feature = "types")]
pub use saa_common::stores;
#[cfg(feature = "utils")]
pub use storage::{load_count, remove_credential, save_credential, load_credential};
#[cfg(feature = "iterator")]
pub use storage::get_all_credentials;



fn credential_from_message(
    storage:   &dyn Storage,
    data_msg:  SignedDataMsg
) -> Result<Credential, AuthError> {
    let initial_id = VERIFYING_CRED_ID.load(storage).unwrap_or_default();

    let id = match data_msg.payload.clone() {
        Some(payload) => {
            payload.validate()?;
            if let Some(id) = payload.credential_id {
                id.to_lowercase()
            } else if let Some(address) = payload.address {
                if address.starts_with("0x") {
                    "0x".to_string() + &address[2..].to_lowercase()
                } else {
                    address.to_lowercase()
                }
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
    _api: &dyn Api,
    storage: &dyn Storage,
    _env: &Env,
    info: &MessageInfo
) -> Result<(), AuthError> {
    if has_credential(storage, &info.sender.to_string()) {
        Ok(())
    } else {
        Err(AuthError::Unauthorized(String::from("Unauthorized caller")))
    }
}


pub fn verify_signed(
    api: &dyn Api,
    #[cfg(feature = "replay")]
    storage: &mut dyn Storage,
    #[cfg(not(feature = "replay"))]
    storage: &dyn Storage,
    env: &Env,
    data: SignedDataMsg
) -> Result<(), AuthError> {
    let credential = credential_from_message(storage, data)?;
    #[cfg(feature = "replay")]
    {   credential.assert_signed_data(storage, env)?;
        saa_common::wasm::storage::increment_account_number(storage)?;
    }
    credential.verify_cosmwasm(api)
}



pub fn save_credentials(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    info: &MessageInfo,
    data: &CredentialData
) -> Result<(), AuthError> {
    data.with_native_caller(info)
        .save(api, storage, env)?;
    Ok(())
}


pub fn update_credentials(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    info: &MessageInfo,
    op: UpdateOperation,
    msg: Option<SignedDataMsg>
) -> Result<(), AuthError> {

    let had_natives = HAS_NATIVES.load(storage)?;

    match op {
        UpdateOperation::Add(data) => {
            ensure!(!data.credentials.is_empty(), AuthError::generic("Must supply at least one credential to add"));
            let data = match msg {
                Some(msg) => {
                    let cred = credential_from_message(storage, msg)?;
                    cred.verify_cosmwasm(api)?;
        
                    #[cfg(feature = "replay")]
                    data.with_credential(cred)
                        .assert_signed_data(storage, env)?;
        
                    data.with_native_caller(info.sender.as_str())
                },
                None => {
                    ensure!(had_natives, AuthError::generic("Must supplly signed message to construct a credential"));
                    verify_caller(api, storage, env, info)?;
                    data
                }
            };
            add_credentials(api, storage, data, had_natives)
        },

        UpdateOperation::Remove(idx) => {
            ensure!(!idx.is_empty(), AuthError::generic("Must supply at least one credential to remove"));
            match msg {
                Some(msg) => verify_signed(api, storage, env, msg)?,
                None => verify_caller(api, storage, env, info)?
            };
            remove_credentials(storage, idx, had_natives)
        }
    }
}





fn add_credentials(
    api: &dyn Api,
    storage: &mut dyn Storage,
    data: CredentialData,
    had_natives: bool
) -> Result<(), AuthError> {
    
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
        save_credential(storage, &id, &cred.info())?;
    }

    if !had_natives && has_natives {
        HAS_NATIVES.save(storage, &true)?;
    }
    Ok(())
}



fn remove_credentials(
    storage: &mut dyn Storage,
    idx: Vec<CredentialId>,
    had_natives: bool
) -> Result<(), AuthError> {
    let all_creds = get_all_credentials(storage)?;
    let left = all_creds.len() - idx.len();
    ensure!(left > 0, AuthError::generic("Must leave at least one credential"));

    println!("Removing credentials Names before {:?}", all_creds.iter().map(|(_, i)| i.name.clone()).collect::<Vec<_>>());
    println!("Removing credentials Ids before {:?}", all_creds.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>());
    println!("Removing credentials with id {:?}", idx);
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
                println!("Removing credential with id {:?}", id);
                remove_credential(storage, &id).is_err()
            } else {
                true
            }
        }).collect();
    
    println!("Removing credentials All after {:?}", remaining.iter().map(|(_, i)| i.name.clone()).collect::<Vec<_>>());
        
    if had_natives && native_changed {
        let still_has = remaining
            .iter()
            .any(|(_, info)| info.name == CredentialName::Native.to_string());
        HAS_NATIVES.save(storage, &still_has)?;
    }

    if verifying_removed {
        let first = all_creds.first().unwrap();
        VERIFYING_CRED_ID.save(storage, &first.0)?;
    }

    Ok(())
}
