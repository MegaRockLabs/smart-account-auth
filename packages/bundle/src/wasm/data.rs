use saa_common::{ 
    wasm::{Api, Env, MessageInfo, Storage,
        storage::{has_credential, increment_account_number, remove_credential, save_credential}
    },
    stores::{CALLER, VERIFYING_CRED_ID},
    AuthError, Verifiable, ensure,
};


use crate::{Credential, CredentialData, CredentialsWrapper, UpdateOperation};


impl CredentialData {
    pub fn with_caller_cosmwasm(&self, info: &MessageInfo) -> Self  {
        self.with_caller(info)
    }
}


#[cfg(feature = "replay")]
impl CredentialData {
    pub fn assert_signed(
        &self, 
        storage: &dyn Storage, 
        env: &Env,
    ) -> Result<(), AuthError> {
        use saa_common::messages::MsgDataToVerify;
    
        let first = self.credentials.first().unwrap();
        let first_data : MsgDataToVerify = saa_common::from_json(&first.message())?;
        first_data.validate_cosmwasm(storage, env)?;
        let nonce = first_data.nonce.clone();
        
        self.credentials().iter().skip(1).map(|c| {
            let data : MsgDataToVerify = saa_common::from_json(&c.message())?;
            ensure!(data.chain_id == first_data.chain_id, AuthError::ChainIdMismatch);
            ensure!(data.contract_address == first_data.contract_address, AuthError::ContractMismatch);
            ensure!(data.nonce == nonce, AuthError::DifferentNonce);
            Ok(())
        }).collect::<Result<(), AuthError> >()?;
        Ok(())
    }
}

#[cfg(feature = "storage")]
impl CredentialData {

    fn assert_cosmwasm(
        &self, 
        api: &dyn Api,
        storage: &dyn Storage, 
        env: &Env,
        info :  &MessageInfo
    ) -> Result<(), AuthError> {
    
        if self.with_caller.unwrap_or(false) {
            self.with_caller_cosmwasm(info).validate()?;
            let caller = CALLER.load(storage).unwrap_or(None);
            if caller.is_some() && caller.unwrap() == info.sender.to_string() {
                return Ok(())
            }
        }  else {
            self.validate()?;
        }
    
        ensure!(
            self.credentials.iter().all(|c| {
                has_credential(storage, &c.id()) && c.verify_cosmwasm(api).is_ok()
            }
            ), 
            AuthError::NotFound
        );
    
        #[cfg(feature = "replay")]
        self.assert_signed(storage, env)?;
    
        Ok(())
    }
    
    
    
    pub fn save_cosmwasm(
        &self, 
        api: &dyn Api, 
        storage: &mut dyn Storage,
        env: &Env, 
        info: &MessageInfo
    ) -> Result<(), AuthError> {
        let data = if self.with_caller.unwrap_or(false) {
            CALLER.save(storage, &Some(info.sender.to_string()))?;
            self.with_caller_cosmwasm(info)
        } else {
            self.clone()
        };
    
        #[cfg(feature = "replay")]
        {
            self.assert_signed(storage, env)?;
            increment_account_number(storage)?;
        }  
    
        let mut verifying_found = false;
    
        if data.primary_index.is_some() {
            if let Credential::Caller(_) = data.primary() {
                // skio the caller since it is can't be used to verify messages
            } else {
                VERIFYING_CRED_ID.save(storage, &data.primary_id())?;
                verifying_found = true;
            }
        }
    
        for cred in self.credentials() {
    
            if let Credential::Caller(_) = cred {
                continue;
            }
    
            cred.verify_cosmwasm(api)?;
    
            if !verifying_found {
                VERIFYING_CRED_ID.save(storage, &cred.id())?;
                verifying_found = true;
            }
            save_credential(storage, &cred.id(), &cred.info())?;
        }
    
        ensure!(verifying_found, AuthError::NoVerifying);
        Ok(())
        
    }



    pub fn update_cosmwasm(
        &self,
        op: UpdateOperation,
        api: &dyn Api, 
        storage: &mut dyn Storage,
        env: &Env, 
        info: &MessageInfo
    ) -> Result<(), AuthError> {
    
        let new = match &op {
            UpdateOperation::Add(data) => data,
            UpdateOperation::Remove(data) => data,
        };
        
        self.assert_cosmwasm(api, storage, env, info)?;
        new.assert_signed(storage, env)?;
    
        #[cfg(feature = "replay")]
        increment_account_number(storage)?;
    
        match op {
            UpdateOperation::Add(data) => {
                for cred in data.credentials() {
                    ensure!(!has_credential(storage, &cred.id()), AuthError::AlreadyExists);
                    cred.save_cosmwasm(api, storage, env, info)?;
                    if data.primary_index.is_some() {
                        let primary = data.primary();
                        if let Credential::Caller(_) = primary {} else {
                            VERIFYING_CRED_ID.save(storage, &cred.id())?;
                        }
                    }
                }
                if data.with_caller.unwrap_or(false) {
                    CALLER.save(storage, &Some(info.sender.to_string()))?;
                }
            },
            UpdateOperation::Remove(data) => {
                for cred in data.credentials() {
                    let id = cred.id();
                    ensure!(VERIFYING_CRED_ID.load(storage)? != id, AuthError::NoVerifying);
                    remove_credential(storage, &id)?;
                }
                if data.with_caller.unwrap_or(false) {
                    CALLER.save(storage, &None)?;
                }
            }
        }
        Ok(())
    }
    
    
    
}

