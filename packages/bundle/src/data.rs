#![allow(unreachable_code)]

use saa_common::{
    format, ensure,
    CredentialId, CredentialName, 
    Vec, Verifiable, AuthError
};
use saa_auth::caller::Caller;
use saa_schema::wasm_serde;

#[cfg(feature = "wasm")]
use saa_common::cosmwasm::{Api, Env, MessageInfo, Storage};

#[cfg(feature = "substrate")]
use saa_common::substrate::{InkEnvironment, InkApi};

#[cfg(all(feature = "wasm", feature = "storage"))]
use saa_common::{storage::*, messages::*};


use crate::{Credential, CredentialsWrapper};



#[wasm_serde]
pub struct CredentialData {
    pub credentials     :  Vec<Credential>,
    pub with_caller     :  Option<bool>,
    pub primary_index   :  Option<u8>,
}


#[wasm_serde]
pub enum UpdateOperation<A = CredentialData> {
    Add(A),
    Remove(A),
}



impl CredentialData {

    pub fn with_caller<C: Into::<Caller>> (&self, cal: C) -> Self {
        let mut credentials = self.credentials.clone();

        let existing = credentials.iter()
                .position(|c| c.name() == CredentialName::Caller);

        if let Some(index) = existing {
            credentials[index] = Credential::Caller(cal.into());
        } else {
            credentials.push(Credential::Caller(cal.into()));
        }
        Self {
            credentials,
            with_caller: Some(true),
            primary_index: self.primary_index,
        }
    }


    #[cfg(feature = "substrate")]
    pub fn with_caller_ink(&self, id: impl AsRef<[u8]>) -> Self {
        self.with_caller(id.as_ref())
    }
    

    #[cfg(feature = "wasm")]
    pub fn with_caller_cosmwasm(&self, info: &MessageInfo) -> Self  {
        self.with_caller(info)
    }


    #[cfg(all(feature = "wasm", feature = "replay"))]
    pub fn assert_signed(
        &self, 
        storage: &dyn Storage, 
        env: &Env,
    ) -> Result<(), AuthError> {
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


    #[cfg(all(feature = "wasm", feature = "storage"))]
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
    


    #[cfg(all(feature = "wasm", feature = "storage"))]
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



    #[cfg(all(feature = "wasm", feature = "storage"))]
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



}




impl CredentialsWrapper for CredentialData {
    type Credential = Credential;

    fn credentials(&self) -> &Vec<Self::Credential> {
        &self.credentials
    }
}



impl Verifiable for CredentialData {

    fn id(&self) -> CredentialId {
        self.primary_id()
    }

    fn validate(&self) -> Result<(), AuthError> {
        let creds = self.credentials();
        let with_caller = self.with_caller.unwrap_or(false);

        if with_caller {
            ensure!(creds
                    .iter()
                    .filter(|c| c.name() == CredentialName::Caller)
                    .count() == 1,
                AuthError::generic("No caller credential found")
            );
        } else if creds.len() == 0 {
            return Err(AuthError::NoCredentials);
        } else if creds.len() > 255 {
            return Err(AuthError::Generic(format!("Too many credentials: {}", creds.len())));
        }

        if let Some(index) = self.primary_index() {
            let len = creds.len() + if with_caller { 1 } else { 0 };
            if *index as usize >= len {
                return Err(AuthError::Generic(format!("Primary index {} is out of bounds", index)));
            }
        }
        creds.iter().map(|c| c.validate()).collect()
    }


    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.validate()?;
        self.credentials().iter().map(|c| c.verify()).collect()
    }


    #[cfg(feature = "substrate")]
    fn verify_ink<'a>(&self, api: InkApi<'a, impl InkEnvironment + Clone>) -> Result<(), AuthError> 
        where Self: Sized
    {
        let with_caller = self.with_caller.unwrap_or(false);
        let creds = if with_caller {
            let caller = api.clone().caller();
            self.with_caller_ink(caller)
        } else {
            self.clone()
        };
        creds.validate()?;
        creds.credentials()
            .iter()
            .map(|c| c.verify_ink(api.clone())).
            collect::<Result<Vec<()>, AuthError>>()?;

        Ok(())
    }

    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self,  api : &dyn Api) -> Result<(), AuthError>  
        where Self: Sized 
    {
        self.validate()?;
        self.credentials()
            .iter()
            .map(|c| c.verify_cosmwasm(api)).
            collect::<Result<Vec<()>, AuthError>>()?;

        Ok(())
    }

}