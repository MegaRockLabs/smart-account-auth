use crate::{
    AuthError, CredentialInfo, CredentialId,
    wasm::Storage,
};

use crate::stores::CREDENTIAL_INFOS;
#[cfg(feature = "replay")]
use crate::stores::ACCOUNT_NUMBER;
#[cfg(feature = "iterator")]
use crate::stores::{HAS_NATIVES, VERIFYING_CRED_ID};


#[cfg(feature = "iterator")]
pub fn load_count(storage: &dyn Storage) -> usize {
    #[cfg(all(feature = "secretwasm", not(feature = "cwasm")))]
    return CREDENTIAL_INFOS.get_len(storage).unwrap_or(0) as usize;
    #[cfg(feature = "cwasm")]
    CREDENTIAL_INFOS.keys(storage, None, None, crate::wasm::Order::Ascending).count()
}

#[cfg(feature = "replay")]
pub fn increment_account_number(
    storage: &mut dyn Storage
) -> Result<(), AuthError> {
    #[cfg(feature = "cwasm")]

    #[cfg(feature = "cwasm")]
    if !ACCOUNT_NUMBER.exists(storage) {
        ACCOUNT_NUMBER.save(storage, &1u128)?;
    } else {
        ACCOUNT_NUMBER.update(storage, |n| 
            Ok::<u128, crate::wasm::StdError>(n + 1)
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



pub fn load_credential(
    storage: &dyn Storage,
    id: CredentialId
) -> Result<CredentialInfo, AuthError> {
    #[cfg(feature = "cwasm")]
    let info = CREDENTIAL_INFOS.load(storage, id).ok();
    #[cfg(all(feature = "secretwasm", not(feature = "cwasm")))]
    let info = CREDENTIAL_INFOS.get(storage, &id);
    crate::ensure!(info.is_some(), AuthError::NotFound);
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




#[cfg(feature = "iterator")]
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
        ACCOUNT_NUMBER.remove(storage);
    }
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



#[cfg(all(feature = "cwasm", feature = "iterator"))]
pub fn get_all_credentials(
    storage: &dyn Storage
) -> Result<Vec<(CredentialId, CredentialInfo)>, AuthError> {
    let credentials = CREDENTIAL_INFOS
    .range(storage, None, None, crate::wasm::Order::Ascending)
    .collect::<Result<Vec<(CredentialId, CredentialInfo)>, crate::wasm::StdError>>()?;
    Ok(credentials)
}


#[cfg(all(feature = "secretwasm", feature = "iterator", not(feature = "cwasm")))]
pub fn get_all_credentials(
    storage: &dyn Storage
) -> Result<Vec<(CredentialId, CredentialInfo)>, AuthError> {
    let credentials = CREDENTIAL_INFOS
    .iter(storage)?
    .collect::<Result<Vec<(CredentialId, CredentialInfo)>, crate::wasm::StdError>>()?;
    Ok(credentials)
}