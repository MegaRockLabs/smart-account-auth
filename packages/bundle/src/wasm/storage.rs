use saa_common::{messages::SignedDataMsg,  
    stores::VERIFYING_CRED_ID,
    wasm::{storage::load_credential_info, Api, Env, Storage}, 
    AuthError
};

use crate::credential::{construct_credential, Credential};

pub use saa_common::wasm::storage::reset_credentials;


fn load_credential(
    storage:   &dyn Storage,
    data_msg:  SignedDataMsg
) -> Result<Credential, AuthError> {
    let initial_id = VERIFYING_CRED_ID.load(storage)?;

    let id = match data_msg.payload.clone() {
        Some(payload) => {
            payload.validate_cosmwasm(storage)?;
            if let Some(id) = payload.credential_id {
                id.to_vec()
            } else if let Some(address) = payload.address {
                address.to_lowercase().as_bytes().to_vec()
            } else {
                initial_id
            }
        }
        None => {
            initial_id
        }
    };
    let info = load_credential_info(storage, id.clone())?;

    construct_credential(
        id, 
        info.name,
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
    let credential = load_credential(storage, data)?;
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
    super::verify_signed_queries(api, storage, env, data)?;
    saa_common::wasm::storage::increment_account_number(storage)?;
    Ok(())
}


#[cfg(feature = "iterator")]
pub fn get_all_credentials(
    storage:  &dyn Storage,
) -> Result<saa_common::AccountCredentials, AuthError> {

    let credentials = saa_common::wasm::storage::get_credentials(storage)?;

    let verifying_id = VERIFYING_CRED_ID.load(storage)?;
    let caller = saa_common::stores::CALLER.load(storage).unwrap_or(None);

    Ok(saa_common::AccountCredentials {
        credentials,
        native_caller: caller.is_some(),
        verifying_id: saa_common::Binary::new(verifying_id),
    })

}