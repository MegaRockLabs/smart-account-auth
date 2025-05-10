

use saa_common::{ensure, wasm::Storage, AuthError, CredentialId};

use super::stores::{CREDENTIAL_INFOS, VERIFYING_CRED_ID};
use crate::{
    credential::construct_credential, 
    messages::SignedDataMsg, 
    Credential, 
    CredentialInfo
};



pub fn load_credential(
    storage: &dyn Storage,
    id: CredentialId
) -> Result<CredentialInfo, AuthError> {
    #[cfg(feature = "cwasm")]
    let info = CREDENTIAL_INFOS.load(storage, id).ok();
    #[cfg(all(feature = "secretwasm", not(feature = "cwasm")))]
    let info = CREDENTIAL_INFOS.get(storage, &id);
    ensure!(info.is_some(), AuthError::NotFound);
    Ok(info.unwrap())
}



pub fn save_credential(
    storage: &mut dyn Storage,
    id: &CredentialId,
    info: &CredentialInfo
) -> Result<(), AuthError> {
    #[cfg(feature = "cwasm")]
    CREDENTIAL_INFOS.save(storage, id.clone(), info)?;
    #[cfg(all(feature = "secretwasm", not(feature = "cwasm")))]
    CREDENTIAL_INFOS.insert(storage, id, info)?;
    Ok(())
}



#[allow(dead_code)]
pub fn remove_credential(
    storage: &mut dyn Storage,
    id: &CredentialId
) -> Result<(), AuthError> {
    #[cfg(feature = "cwasm")]
    CREDENTIAL_INFOS.remove(storage, id.clone());
    #[cfg(all(feature = "secretwasm", not(feature = "cwasm")))]
    CREDENTIAL_INFOS.remove(storage, id)?;
    Ok(())
}





pub fn has_credential(
    storage: &dyn Storage,
    id: &CredentialId
) -> bool {
    #[cfg(feature = "cwasm")]
    return CREDENTIAL_INFOS.has(storage, id.clone());
    #[cfg(all(feature = "secretwasm", not(feature = "cwasm")))]
    return CREDENTIAL_INFOS.contains(storage, id);
}






pub(crate) fn credential_from_payload(
    storage:  &dyn Storage,
    data_msg: SignedDataMsg
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
    let info = load_credential(storage, id.clone())?;

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

