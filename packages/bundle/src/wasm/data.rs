use saa_common::{ 
    stores::{HAS_NATIVES, VERIFYING_CRED_ID}, wasm::{
        storage::save_credential, 
        Api, Env, Storage
    }, AuthError, Verifiable
};



#[cfg(feature = "traits")]
use crate::CredentialsWrapper;


#[cfg(feature = "replay")]
impl crate::CredentialData {
    pub fn assert_signed_data(
        &self, 
        storage: &dyn Storage, 
        env: &Env,
    ) -> Result<(), AuthError> {
        use saa_common::{
            messages::MsgDataToVerify,
            from_json, ensure
        };
        let credentials : Vec<&crate::credential::Credential> = self.credentials
            .iter().filter(|c| 
                c.name() != crate::credential::CredentialName::Native 
                //&& !c.message().is_empty()
            )
            .collect();

        if credentials.is_empty() { return Ok(()) }
        let first = credentials.first().unwrap();

        let first_data : MsgDataToVerify   = from_json(&first.message())
                .map_err(|_| AuthError::InvalidSignedData)?;

        first_data.validate(storage, env)?;
        let nonce = first_data.nonce.clone();
        
        credentials.into_iter().skip(1).try_for_each(|c| {
            let data : MsgDataToVerify = from_json(&c.message()).map_err(|_| AuthError::InvalidSignedData)?;
            ensure!(data.chain_id == first_data.chain_id, AuthError::ChainIdMismatch);
            ensure!(data.contract_address == first_data.contract_address, AuthError::ContractMismatch);
            ensure!(data.nonce == nonce, AuthError::DifferentNonce);
            Ok::<(), AuthError>(())
        })?;
        Ok(())
    }
}


#[allow(unused_variables)]
impl crate::CredentialData {

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
            saa_common::wasm::storage::increment_account_number(storage)?;
        }
        let mut has_natives = false;
        for cred in self.credentials.iter() {
            let id = &cred.id();
            //println!("Saving credential: {:?} with id {:?}", cred.name(), id);
            cred.verify_cosmwasm(api)?;
            save_credential(storage, id, &cred.info())?;
            if cred.name() == crate::credential::CredentialName::Native { has_natives = true }
        }
        HAS_NATIVES.save(storage, &has_natives)?;

        #[cfg(feature = "traits")]
        let id: String = self.primary_id();
        #[cfg(not(feature = "traits"))]
        let id = self.credentials.first().unwrap().id();

        VERIFYING_CRED_ID.save(storage, &id)?;
        Ok(self.clone())
    }


}


