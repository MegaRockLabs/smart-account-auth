use crate::{
    stores::{ACCOUNT_NUMBER, CALLER, CREDENTIAL_INFOS, VERIFYING_CRED_ID}, 
    AuthError, CredentialInfo
};

use crate::wasm::{Storage, StdError};
use crate::CredentialId;


pub fn increment_account_number(
    storage: &mut dyn Storage
) -> Result<(), AuthError> {
    #[cfg(feature = "cosmwasm")]
    if !ACCOUNT_NUMBER.exists(storage) {
        ACCOUNT_NUMBER.save(storage, &1u128)?;
    } else {
        ACCOUNT_NUMBER.update(storage, |n| Ok::<u128, StdError>(n + 1))?;
    }
    #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm")))]
    if ACCOUNT_NUMBER.is_empty(storage) {
        ACCOUNT_NUMBER.save(storage, &1u128)?;
    } else {
        ACCOUNT_NUMBER.update(storage, |n| Ok::<u128, StdError>(n + 1))?;
    }
    Ok(())
}



pub fn load_credential_info(
    storage: &dyn Storage,
    id: CredentialId
) -> Result<CredentialInfo, AuthError> {
    #[cfg(feature = "cosmwasm")]
    let info = CREDENTIAL_INFOS.load(storage, id).ok();
    #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm")))]
    let info = CREDENTIAL_INFOS.get(storage, &id);
    crate::ensure!(info.is_some(), AuthError::NotFound);
    Ok(info.unwrap())
}



pub fn save_credential(
    storage: &mut dyn Storage,
    id: &CredentialId,
    info: &CredentialInfo
) -> Result<(), AuthError> {
    #[cfg(feature = "cosmwasm")]
    CREDENTIAL_INFOS.save(storage, id.clone(), info)?;
    #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm")))]
    CREDENTIAL_INFOS.insert(storage, id, info)?;
    Ok(())
}


pub fn remove_credential(
    storage: &mut dyn Storage,
    id: &CredentialId
) -> Result<(), AuthError> {
    #[cfg(feature = "cosmwasm")]
    CREDENTIAL_INFOS.remove(storage, id.clone());
    #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm")))]
    CREDENTIAL_INFOS.remove(storage, id)?;
    Ok(())
}


pub fn reset_credentials(
    storage: &mut dyn Storage,
) -> Result<(), AuthError> {
    VERIFYING_CRED_ID.remove(storage);
    CALLER.remove(storage);
    #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm")))]
    {
        let keys : Vec<CredentialId> = CREDENTIAL_INFOS
            .iter_keys(storage)?.map(|k| k.unwrap()).collect();

        for key in keys {
            CREDENTIAL_INFOS.remove(storage, &key)?;
        }
    }
    #[cfg(feature = "cosmwasm")]
    CREDENTIAL_INFOS.clear(storage);
    Ok(())
}


pub fn has_credential(
    storage: &dyn Storage,
    id: &CredentialId
) -> bool {
    #[cfg(feature = "cosmwasm")]
    return CREDENTIAL_INFOS.has(storage, id.clone());
    #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm")))]
    return CREDENTIAL_INFOS.contains(storage, id);
}







#[cfg(all(feature = "cosmwasm", feature = "iterator"))]
pub fn get_credentials(
    storage: &dyn Storage
) -> Result<Vec<(crate::Binary, CredentialInfo)>, AuthError> {
    let credentials = CREDENTIAL_INFOS
    .range(storage, None, None, crate::wasm::Order::Ascending)
    .map(|item| {
        let (id, info) = item?;
        Ok((id.into(), CredentialInfo {
            name: info.name,
            hrp: info.hrp,
            extension: info.extension,
        }))
    })
    .collect::<Result<Vec<(crate::Binary, CredentialInfo)>, AuthError>>()?;
    Ok(credentials)
}


#[cfg(all(feature = "secretwasm", feature = "iterator", not(feature = "cosmwasm")))]
pub fn get_credentials(
    storage: &dyn Storage
) -> Result<Vec<(crate::Binary, CredentialInfo)>, AuthError> {
    let credentials = CREDENTIAL_INFOS
    .iter(storage)?
    .map(|item| {
        let (id, info) = item?;
        Ok((
            crate::Binary::new(id), 
            CredentialInfo {
                name: info.name,
                hrp: info.hrp,
                extension: info.extension,
        }))
    })
    .collect::<Result<Vec<(crate::Binary, CredentialInfo)>, AuthError>>()?;

    Ok(credentials)
}