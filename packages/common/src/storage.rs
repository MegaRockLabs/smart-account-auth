#[cfg(feature = "cosmwasm")]
mod cosmwasm;

#[cfg(feature = "secretwasm")]
mod secretwasm;

#[cfg(any(feature = "cosmwasm_2_1", all(feature = "cosmwasm", not(feature = "secretwasm"))))]
pub use cosmwasm::*;

#[cfg(all(feature = "secretwasm", not(feature = "cosmwasm_2_1")))]
pub use secretwasm::*;


#[cfg(feature = "wasm")]
mod inner {

    use super::*;
    use crate::{AuthError, CredentialInfo};
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
        #[cfg(any(feature = "cosmwasm_2_1", all(feature = "cosmwasm", not(feature = "secretwasm"))))]
        let info = cosmwasm::CREDENTIAL_INFOS.load(storage, id).ok();
        #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm_2_1")))]
        let info = secretwasm::CREDENTIAL_INFOS.get(
            storage, &id
        );
        crate::ensure!(info.is_some(), AuthError::NotFound);
        Ok(info.unwrap())
    }


    #[cfg(
        all(
            any(feature = "cosmwasm_2_1", all(feature = "cosmwasm", not(feature = "secretwasm"))
        ), 
        feature = "iterator"
        )
    )]
    pub fn get_credentials(
        storage: &dyn cosmwasm_std::Storage
    ) -> Result<Vec<(crate::Binary, CredentialInfo)>, AuthError> {

        let credentials = cosmwasm::CREDENTIAL_INFOS
        .range(storage, None, None, crate::cosmwasm::Order::Ascending)
        .map(|item| {
            let (id, info) = item?;
            Ok((
                id.into(), 
                CredentialInfo {
                    name: info.name,
                    hrp: info.hrp,
                    extension: info.extension,
            }))
        })
        .collect::<Result<Vec<(crate::Binary, CredentialInfo)>, AuthError>>()?;
        Ok(credentials)
    }

    #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm_2_1"), feature = "iterator"))]
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
        #[cfg(any(feature = "cosmwasm_2_1", all(feature = "cosmwasm", not(feature = "secretwasm"))))]
        cosmwasm::CREDENTIAL_INFOS.save(storage, id.clone(), info)?;
        #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm_2_1")))]
        secretwasm::CREDENTIAL_INFOS.insert(storage, id, info)?;
        Ok(())
    }

    pub fn has_credential(
        storage: &dyn crate::cosmwasm::Storage,
        id: &crate::CredentialId
    ) -> bool {
        #[cfg(any(feature = "cosmwasm_2_1", all(feature = "cosmwasm", not(feature = "secretwasm"))))]
        return cosmwasm::CREDENTIAL_INFOS.has(storage, id.clone());
        #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm_2_1")))]
        return secretwasm::CREDENTIAL_INFOS.contains(storage, id);
    }

    pub fn remove_credential(
        storage: &mut dyn crate::cosmwasm::Storage,
        id: &crate::CredentialId
    ) -> Result<(), AuthError> {
        #[cfg(any(feature = "cosmwasm_2_1", all(feature = "cosmwasm", not(feature = "secretwasm"))))]
        cosmwasm::CREDENTIAL_INFOS.remove(storage, id.clone());
        #[cfg(all(feature = "secretwasm", not(feature = "cosmwasm_2_1")))]
        secretwasm::CREDENTIAL_INFOS.remove(storage, id)?;
        Ok(())
    }


}
#[cfg(feature = "wasm")]
pub use inner::*;