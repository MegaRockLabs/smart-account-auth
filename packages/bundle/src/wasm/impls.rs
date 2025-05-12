use crate::{credential::{CredentialInfo, CredentialName}, storage::account_number, Credential};
use saa_common::{wasm::{Addr, Api}, AuthError, CredentialId};

#[cfg(feature = "storage")]
use {
    saa_common::{wasm::{Env, Storage}, Verifiable},
    crate::wasm::storage::stores::{HAS_NATIVES, VERIFYING_CRED_ID},
};

#[cfg(feature = "replay")]
use {
    saa_common::ensure,
    crate::messages::{MsgDataToSign, MsgDataToVerify}
};

// Allow usage of `CosmosMsg<SignedDataMsg>` in CosmWasm contracts
impl saa_common::wasm::CustomMsg for crate::messages::SignedDataMsg {}


impl Credential {

    pub fn is_cosmos_derivable(&self) -> bool {
        #[allow(unused_mut)]
        let mut ok = self.hrp().is_some();
        #[cfg(feature = "cosmos")]
        {
            ok = ok && self.name() == CredentialName::CosmosArbitrary;
        }
        ok
    }

    pub fn cosmos_address(&self, api: &dyn Api) -> Result<Addr, AuthError> {
        use saa_common::utils::*;
        let id = self.id();
        let name = self.name();
        if name == CredentialName::Native {
            let addr = api.addr_validate(&id)?;
            return Ok(addr)
        }
        #[cfg(all(feature = "injective", feature="ethereum"))]
        {
            if name == CredentialName::EthPersonalSign {
                return Ok(Addr::unchecked(
                    pubkey_to_address(
                        id.as_bytes(), "inj"
                    )?
                ))
            } 
        }
        Ok(match self.hrp() {
            Some(hrp) => Addr::unchecked(
                pubkey_to_address(id.as_bytes(), &hrp)?
            ),
            None => {
                let canon = pubkey_to_canonical(id.as_bytes());
                let addr = api.addr_humanize(&canon)?;
                addr
            }
        })
    }

}



impl CredentialInfo {
    

    pub fn cosmos_address(&self, api: &dyn Api, id: CredentialId) -> Result<Addr, crate::AuthError> {
        use saa_common::utils::*;
        let name = self.name.clone();
        if name == CredentialName::Native {
            let addr = api.addr_validate(&id)?;
            return Ok(addr)
        }
        #[cfg(all(feature = "injective", feature="ethereum"))]
        {
            if name == CredentialName::EthPersonalSign {
                return Ok(Addr::unchecked(
                    pubkey_to_address(
                        id.as_bytes(), "inj"
                    )?
                ))
            } 
        }
        Ok(match &self.hrp {
            Some(hrp) => Addr::unchecked(
                pubkey_to_address(id.as_bytes(), &hrp)?
            ),
            None => {
                let canon = pubkey_to_canonical(
                    id.as_bytes()
                );
                let addr = api.addr_humanize(&canon)?;
                addr
            }
        })
    }
}







#[cfg(all(feature = "traits", feature = "storage"))]
use crate::traits::CredentialsWrapper;



#[allow(unused_variables)]
#[cfg(feature = "storage")]
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
            crate::wasm::storage::increment_account_number(storage)?;
        }
        let mut has_natives = false;
        for cred in self.credentials.iter() {
            let id = &cred.id();
            //println!("Saving credential: {:?} with id {:?}", cred.name(), id);
            cred.verify_cosmwasm(api)?;
            crate::wasm::storage::utils::save_credential(storage, id, &cred.info())?;
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





#[cfg(feature = "replay")]
impl crate::CredentialData {
    pub fn assert_signed_data(
        &self, 
        storage: &dyn Storage, 
        env: &Env,
    ) -> Result<(), AuthError> {
        use saa_common::{from_json, ensure};
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



#[cfg(feature = "replay")]
impl MsgDataToVerify {
    pub fn check_fields(&self, env: &Env) -> Result<(), AuthError> {
        ensure!(self.chain_id == env.block.chain_id, AuthError::ChainIdMismatch);
        ensure!(self.contract_address == env.contract.address.to_string(), AuthError::ContractMismatch);
        ensure!(self.nonce.len() > 0, AuthError::MissingData("Nonce".to_string()));
        Ok(())
    }
    pub fn validate(&self, store: &dyn Storage, env: &Env) -> Result<(), AuthError> {
        self.check_fields(env)?;
        ensure!(self.nonce == account_number(store).to_string(), AuthError::DifferentNonce);
        Ok(())
    }
}


#[cfg(feature = "replay")]
impl<M> MsgDataToSign<M> {
    pub fn check_fields(&self, env: &Env) -> Result<(), AuthError> {
        Into::<MsgDataToVerify>::into(self).check_fields(env)
    }
    pub fn validate(&self, store: &dyn Storage, env: &Env) -> Result<(), AuthError> {
        Into::<MsgDataToVerify>::into(self).validate(store, env)
    }
}