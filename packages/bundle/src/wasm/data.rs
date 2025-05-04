use saa_common::{ 
    ensure, stores::{CALLER, HAS_NATIVES, VERIFYING_CRED_ID}, wasm::{
        storage::{has_credential, increment_account_number, remove_credential, save_credential}, 
        Api, Env, MessageInfo, Storage
    }, AuthError, Verifiable
};


use crate::{credential::CredentialName, Credential, CredentialData, CredentialsWrapper, UpdateOperation};



#[cfg(feature = "replay")]
impl CredentialData {
    fn assert_signed_data(
        &self, 
        storage: &dyn Storage, 
        env: &Env,
    ) -> Result<(), AuthError> {
        use saa_common::{
            messages::MsgDataToVerify,
            from_json
        };

        let credentials : Vec<&Credential> = self.credentials
            .iter().filter(|c| 
                c.name() != CredentialName::Native 
                //&& !c.message().is_empty()
            )
            .collect();

        if credentials.is_empty() { return Ok(()) }
        let first = credentials.first().unwrap();

        let first_data : MsgDataToVerify   = from_json(&first.message())
                .map_err(|_| AuthError::InvalidSignedData)?;

        first_data.validate(storage, env)?;
        let nonce = first_data.nonce.clone();
        
        credentials.iter().skip(1).map(|c| {
            let data : MsgDataToVerify = from_json(&c.message()).map_err(|_| AuthError::InvalidSignedData)?;
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

    pub fn save(
        &self, 
        api: &dyn Api, 
        storage: &mut dyn Storage,
        env: &Env, 
        info: &MessageInfo
    ) -> Result<Self, AuthError> {
    
        #[cfg(feature = "replay")]
        {
            self.assert_signed_data(storage, env)?;
            increment_account_number(storage)?;
        }

        let data = self.with_native_caller(info);

        let mut has_natives = false;

        for cred in self.credentials() {
            let info = cred.info();
            ensure!(!has_credential(storage, &cred.id()), AuthError::AlreadyExists);
            cred.verify_cosmwasm(api)?;
            save_credential(storage, &cred.id(), &info)?;
            if cred.name() == CredentialName::Native { has_natives = true }
        }

        HAS_NATIVES.save(storage, &has_natives)?;
        VERIFYING_CRED_ID.save(storage, &data.primary_id())?;
        Ok(data)
        
    }



    pub fn update(
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
        
        new.assert_signed_data(storage, env)?;
    
        #[cfg(feature = "replay")]
        increment_account_number(storage)?;
    
        match op {
            UpdateOperation::Add(data) => {
                for cred in data.credentials() {
                    ensure!(!has_credential(storage, &cred.id()), AuthError::AlreadyExists);
                    cred.save_cosmwasm(api, storage, env, info)?;
                    if data.primary_index.is_some() {
                        let primary = data.primary();
                        if let Credential::Native(_) = primary {} else {
                            VERIFYING_CRED_ID.save(storage, &cred.id())?;
                        }
                    }
                }
                if data.use_native.unwrap_or(false) {
                    CALLER.save(storage, &Some(info.sender.to_string()))?;
                }
            },
            UpdateOperation::Remove(data) => {
                for cred in data.credentials() {
                    let id = cred.id();
                    ensure!(VERIFYING_CRED_ID.load(storage)? != id, AuthError::NoVerifying);
                    remove_credential(storage, &id)?;
                }
                if data.use_native.unwrap_or(false) {
                    CALLER.save(storage, &None)?;
                }
            }
        }
        Ok(())
    }
    
    
    
}

