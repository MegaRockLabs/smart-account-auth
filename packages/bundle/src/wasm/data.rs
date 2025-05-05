use saa_common::{ 
    ensure, stores::{HAS_NATIVES, VERIFYING_CRED_ID}, wasm::{
        storage::{increment_account_number, save_credential}, 
        Api, Env, Storage
    }, AuthError, Verifiable
};


use crate::{credential::CredentialName, Credential, CredentialData, CredentialsWrapper};



#[cfg(feature = "replay")]
impl CredentialData {
    pub fn assert_signed_data(
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
    ) -> Result<Self, AuthError> {
        self.validate()?;
        #[cfg(feature = "replay")]
        {
            self.assert_signed_data(storage, env)?;
            increment_account_number(storage)?;
        }
        let mut has_natives = false;
        for cred in self.credentials() {
            let id = &cred.id();
            //println!("Saving credential: {:?} with id {:?}", cred.name(), id);
            cred.verify_cosmwasm(api)?;
            save_credential(storage, id, &cred.info())?;
            if cred.name() == CredentialName::Native { has_natives = true }
        }
        HAS_NATIVES.save(storage, &has_natives)?;
        VERIFYING_CRED_ID.save(storage, &self.primary_id())?;
        Ok(self.clone())
    }


}


