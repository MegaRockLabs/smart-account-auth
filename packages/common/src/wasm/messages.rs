
use crate::{ensure, AuthError};
use crate::messages::{AuthPayload, MsgDataToSign, MsgDataToVerify, SignedDataMsg};
use crate::wasm::{CustomMsg, Storage, Env};


impl<E> AuthPayload<E> {

    pub fn validate_cosmwasm(
        &self, 
        #[cfg(feature = "storage")]
        store: &dyn Storage

    ) -> Result<(), AuthError> {

        self.validate()?;
        
        #[cfg(feature = "storage")]
        if self.credential_id.is_some() {
            let info_res = super::storage::load_credential_info(
                store, 
                self.credential_id.clone().unwrap().to_vec()
            );
            ensure!(info_res.is_ok(), AuthError::NotFound);

            if self.hrp.is_some() {
                let name = info_res.unwrap().name;
                ensure!(
                    name == crate::CredentialName::CosmosArbitrary || name == crate::CredentialName::Secp256k1,
                    AuthError::generic("'hrp' can only be passed for 'cosmos-arbitrary' or 'secp256k1'")
                );
            }
        }
        Ok(())
    }
    
}




impl MsgDataToVerify {
    pub fn validate_cosmwasm(
        &self, 
        #[cfg(feature = "replay")]
        store: &dyn Storage, 
        env: &Env
    ) -> Result<(), AuthError> {
        ensure!(self.chain_id == env.block.chain_id, AuthError::ChainIdMismatch);
        ensure!(self.contract_address == env.contract.address.to_string(), AuthError::ContractMismatch);
        ensure!(self.nonce.len() > 0, AuthError::MissingData("Nonce".to_string()));
        #[cfg(feature = "replay")]
        ensure!(crate::stores::ACCOUNT_NUMBER.load(store)
            .unwrap_or_default().to_string() == self.nonce, AuthError::DifferentNonce);
        Ok(())
    }
}


impl<M> MsgDataToSign<M> {
    pub fn validate_cosmwasm(
        &self, 
        #[cfg(feature = "replay")]
        store: &dyn Storage, 
        env: &Env
    ) -> Result<(), AuthError> {
        Into::<MsgDataToVerify>::into(self)
        .validate_cosmwasm(
            #[cfg(feature = "replay")]
            store,
            env
        )
    }
}




impl CustomMsg for SignedDataMsg {}