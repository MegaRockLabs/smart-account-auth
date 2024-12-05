#[cfg(feature = "cosmwasm")]
mod cosmwasm;

#[cfg(all(feature = "secretwasm", not(feature = "cosmwasm")))]
mod secretwasm;

#[cfg(feature = "cosmwasm")]
pub use cosmwasm::*;

#[cfg(all(feature = "secretwasm", not(feature = "cosmwasm")))]
pub use secretwasm::*;


#[cfg(feature = "wasm")]
mod inner {

    use super::*;
    use crate::{AuthError, CredentialInfo};
    use crate::cosmwasm::StdError;

    #[cfg(feature = "replay")]
    pub fn increment_nonce(
        storage: &mut dyn crate::cosmwasm::Storage
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

    pub fn get_cred_info(
        storage: &dyn crate::cosmwasm::Storage,
        id: crate::CredentialId
    ) -> Result<CredentialInfo, AuthError> {
        #[cfg(feature = "cosmwasm")]
        let info = cosmwasm::CREDENTIAL_INFOS.load(storage, id).ok();
        #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm")))]
        let info = secretwasm::CREDENTIAL_INFOS.get(storage, &id);
        crate::ensure!(info.is_some(), AuthError::NotFound);
        Ok(info.unwrap())
    }


    #[cfg(all(feature = "cosmwasm", feature = "iterator"))]
    pub fn get_credentials(
        storage: &dyn cosmwasm_std::Storage
    ) -> Result<Vec<(crate::Binary, CredentialInfo)>, AuthError> {

        let credentials = cosmwasm::CREDENTIAL_INFOS
        .range(storage, None, None, crate::cosmwasm::Order::Ascending)
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

    #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm"), feature = "iterator"))]
    pub fn get_credentials(
        storage: &dyn secretwasm_std::Storage
    ) -> Result<Vec<(crate::Binary, CredentialInfo)>, AuthError> {
        let credentials = secretwasm::CREDENTIAL_INFOS
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

   pub  fn save_credential(
        storage: &mut dyn crate::cosmwasm::Storage,
        id: &crate::CredentialId,
        info: &CredentialInfo
    ) -> Result<(), AuthError> {
        #[cfg(feature = "cosmwasm")]
        cosmwasm::CREDENTIAL_INFOS.save(storage, id.clone(), info)?;
        #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm")))]
        secretwasm::CREDENTIAL_INFOS.insert(storage, id, info)?;
        Ok(())
    }

    pub fn has_credential(
        storage: &dyn crate::cosmwasm::Storage,
        id: &crate::CredentialId
    ) -> bool {
        #[cfg(feature = "cosmwasm")]
        return cosmwasm::CREDENTIAL_INFOS.has(storage, id.clone());
        #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm")))]
        return secretwasm::CREDENTIAL_INFOS.contains(storage, id);
    }

    pub fn remove_credential(
        storage: &mut dyn crate::cosmwasm::Storage,
        id: &crate::CredentialId
    ) -> Result<(), AuthError> {
        #[cfg(feature = "cosmwasm")]
        cosmwasm::CREDENTIAL_INFOS.remove(storage, id.clone());
        #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm")))]
        secretwasm::CREDENTIAL_INFOS.remove(storage, id)?;
        Ok(())
    }


}
#[cfg(feature = "wasm")]
pub use inner::*;