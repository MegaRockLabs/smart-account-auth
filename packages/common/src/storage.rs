mod cosmwasm;

#[cfg(feature = "secretwasm")]
mod secretwasm;

#[cfg(all(feature = "cosmwasm", not(feature = "secretwasm")))]
pub use cosmwasm::*;

#[cfg(feature = "secretwasm")]
pub use secretwasm::*;


#[cfg(feature = "wasm")]
mod inner {

    use super::*;
    use crate::{AuthError, Binary, CredentialInfo};
    use crate::cosmwasm::StdError;

    pub fn increment_acc_number(
        storage: &mut dyn crate::cosmwasm::Storage
    ) -> Result<(), AuthError> {
        ACCOUNT_NUMBER.update(storage, |n| Ok::<u128, StdError>(n + 1))?;
        Ok(())
    }


    pub fn get_cred_info(
        storage: &dyn crate::cosmwasm::Storage,
        id: crate::CredentialId
    ) -> Result<CredentialInfo, AuthError> {
        #[cfg(not(feature = "secretwasm"))]
        let info = cosmwasm::CREDENTIAL_INFOS.load(storage, id).ok();
         #[cfg(feature = "secretwasm")]
        let info = secretwasm::CREDENTIAL_INFOS.get(
            storage, &id
        );
        crate::ensure!(info.is_some(), AuthError::NotFound);
        Ok(info.unwrap())
    }


    #[cfg(all(not(feature = "secretwasm"), feature = "iterator"))]
    pub fn get_credentials(
        storage: &dyn cosmwasm_std::Storage
    ) -> Result<Vec<(Binary, CredentialInfo)>, AuthError> {
        let credentials = cosmwasm::CREDENTIAL_INFOS
        .range(storage, None, None, crate::cosmwasm::Order::Ascending)
        .map(|item| {
            let (id, info) = item?;
            Ok((
                Binary::new(id), 
                CredentialInfo {
                    name: info.name,
                    hrp: info.hrp,
                    extension: info.extension,
            }))
        })
        .collect::<Result<Vec<(Binary, CredentialInfo)>, AuthError>>()?;
        Ok(credentials)
    }

    #[cfg(all(feature = "secretwasm", feature = "iterator"))]
    pub fn get_credentials(
        storage: &dyn secretwasm_std::Storage
    ) -> Result<Vec<(Binary, CredentialInfo)>, AuthError> {
        let credentials = secretwasm::CREDENTIAL_INFOS
        .iter(storage)?
        .map(|item| {
            let (id, info) = item?;
            Ok((
                Binary::new(id), 
                CredentialInfo {
                    name: info.name,
                    hrp: info.hrp,
                    extension: info.extension,
            }))
        })
        .collect::<Result<Vec<(Binary, CredentialInfo)>, AuthError>>()?;

        Ok(credentials)
    }

   pub  fn save_credential(
        storage: &mut dyn crate::cosmwasm::Storage,
        id: &crate::CredentialId,
        info: &CredentialInfo
    ) -> Result<(), AuthError> {
        #[cfg(not(feature = "secretwasm"))]
        cosmwasm::CREDENTIAL_INFOS.save(storage, id.clone(), info)?;
        #[cfg(feature = "secretwasm")]
        secretwasm::CREDENTIAL_INFOS.insert(storage, id, info)?;
        Ok(())
    }

    pub fn has_credential(
        storage: &dyn crate::cosmwasm::Storage,
        id: &crate::CredentialId
    ) -> bool {
        #[cfg(not(feature = "secretwasm"))]
        return cosmwasm::CREDENTIAL_INFOS.has(storage, id.clone());
        #[cfg(feature = "secretwasm")]
        return secretwasm::CREDENTIAL_INFOS.contains(storage, id);
    }

    pub fn remove_credential(
        storage: &mut dyn crate::cosmwasm::Storage,
        id: &crate::CredentialId
    ) -> Result<(), AuthError> {
        #[cfg(not(feature = "secretwasm"))]
        cosmwasm::CREDENTIAL_INFOS.remove(storage, id.clone());
        #[cfg(feature = "secretwasm")]
        secretwasm::CREDENTIAL_INFOS.remove(storage, id)?;
        Ok(())
    }


}
#[cfg(feature = "wasm")]
pub use inner::*;