
use crate::{ensure, AuthError};
use crate::messages::{MsgDataToSign, MsgDataToVerify, SignedDataMsg};
use crate::wasm::{CustomMsg, Storage, Env};





impl MsgDataToVerify {
    pub fn validate(
        &self, 
        #[cfg(feature = "replay")]
        store: &dyn Storage, 
        env: &Env
    ) -> Result<(), AuthError> {
        ensure!(self.chain_id == env.block.chain_id, AuthError::ChainIdMismatch);
        ensure!(self.contract_address == env.contract.address.to_string(), AuthError::ContractMismatch);
        ensure!(self.nonce.len() > 0, AuthError::MissingData("Nonce".to_string()));
        #[cfg(feature = "replay")]
        ensure!(
            self.nonce == crate::stores::ACCOUNT_NUMBER.load(store).unwrap_or_default().to_string(), 
            AuthError::DifferentNonce);
        Ok(())
    }
}


impl<M> MsgDataToSign<M> {
    pub fn validate(
        &self, 
        #[cfg(feature = "replay")]
        store: &dyn Storage, 
        env: &Env
    ) -> Result<(), AuthError> {
        Into::<MsgDataToVerify>::into(self)
        .validate(
            #[cfg(feature = "replay")]
            store,
            env
        )
    }
}




impl CustomMsg for SignedDataMsg {}