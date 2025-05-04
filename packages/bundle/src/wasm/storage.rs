use core::str::FromStr;

use saa_common::{messages::SignedDataMsg,  
    stores::VERIFYING_CRED_ID,
    wasm::{Api, Env, Storage, storage}, 
    AuthError
};

use crate::credential::{
    construct_credential, 
    Credential, 
    CredentialName
};

pub use storage::reset_credentials;

#[cfg(feature = "types")]
pub use saa_common::stores;
#[cfg(feature = "utils")]
pub use storage::{load_count, remove_credential, save_credential, load_credential, remove_credential_smart};
#[cfg(feature = "iterator")]
pub use storage::get_all_credentials;





fn credential_from_message(
    storage:   &dyn Storage,
    data_msg:  SignedDataMsg
) -> Result<Credential, AuthError> {
    let initial_id = VERIFYING_CRED_ID.load(storage)?;

    let id = match data_msg.payload.clone() {
        Some(payload) => {
            payload.validate()?;
            if let Some(id) = payload.credential_id {
                id
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




pub fn verify_signed_queries(
    api: &dyn Api,
    storage: &dyn Storage,
    env: &Env,
    data: SignedDataMsg
) -> Result<(), AuthError> {
    let credential = credential_from_message(storage, data)?;
    credential.assert_cosmwasm(api, storage, env)?;
    Ok(())
}


#[cfg(feature = "replay")]
pub fn verify_signed_actions(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    data: SignedDataMsg
) -> Result<(), AuthError> {
    verify_signed_queries(api, storage, env, data)?;
    saa_common::wasm::storage::increment_account_number(storage)?;
    Ok(())
}

/* 
#[cfg(feature = "iterator")]
pub fn get_all_credentials(
    storage:  &dyn Storage,
) -> Result<saa_common::AccountCredentials, AuthError> {

    let credentials = saa_common::wasm::storage::get_all_credentials(storage)?;
    let verifying_id = VERIFYING_CRED_ID.load(storage)?;

    let native_caller = saa_common::stores::CALLER.load(
        storage
    ).ok().flatten();

    Ok(saa_common::AccountCredentials {
        credentials,
        native_caller,
        verifying_id,
    })

} */