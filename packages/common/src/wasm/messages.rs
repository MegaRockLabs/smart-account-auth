
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
        if let Some(credential_id) = &self.credential_id {
            let info_res = super::storage::load_credential_info(
                store, 
                credential_id.clone()
            );
            ensure!(info_res.is_ok(), AuthError::NotFound);
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