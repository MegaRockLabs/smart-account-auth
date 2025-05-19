use crate::{msgs::SignedDataMsg, credential::{Credential, CredentialInfo, CredentialName}};
use saa_common::{wasm::{Addr, Api, CustomMsg}, AuthError, CredentialId};



// Allow usage of `CosmosMsg<SignedDataMsg>` in CosmWasm contracts
impl CustomMsg for SignedDataMsg {}


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
        Ok(match &self.hrp {
            Some(hrp) => api.addr_validate(&pubkey_to_address(id.as_bytes(), &hrp)?)?,
            None => api.addr_humanize(&pubkey_to_canonical(id.as_bytes()))?,
        })
    }
}









#[cfg(feature = "replay")]
pub fn convert_validate(
    data: impl AsRef<[u8]>,
    env: &Env,
    nonce: u64
) -> Result<(), AuthError> {
    let msg : crate::msgs::MsgDataToVerify = saa_common::from_json(data)
                    .map_err(|_| AuthError::Convertation("MsgDataToVerify".to_string()))?;
    msg.validate(env, nonce)?;
    Ok(())
}






#[cfg(feature = "replay")]
impl crate::CredentialData {
    pub fn checked_replay(
        &self, 
        env: &Env,
        nonce: u64,
    ) -> Result<(), AuthError> {
        
        let credentials : Vec<&crate::credential::Credential> = self.credentials
            .iter().filter(|c| 
                c.name() != crate::credential::CredentialName::Native 
            )
            .collect();

        if credentials.is_empty() { return Ok(()) }
     
        credentials
            .into_iter()
            .try_for_each(|c| convert_validate(c.message(), env, nonce))?;
                
        Ok(())
    }
}



#[cfg(feature = "replay")]
use {saa_common::{ensure, ReplayError, wasm::Env}};


#[cfg(feature = "replay")]
impl crate::msgs::MsgDataToVerify {
    pub fn validate(&self, env: &Env, expected: u64 ) -> Result<(), ReplayError> {
        ensure!(self.chain_id == env.block.chain_id, ReplayError::ChainIdMismatch);
        ensure!(self.contract_address == env.contract.address.to_string(), ReplayError::ContractMismatch);
        let signed = self.nonce.u64();
        ensure!(signed == expected, ReplayError::DifferentNonce(signed, expected));
        Ok(())
    }
}


#[cfg(feature = "replay")]
impl<M : serde::de::DeserializeOwned> crate::msgs::MsgDataToSign<M> {
    pub fn validate(&self, env: &Env, nonce: u64) -> Result<(), ReplayError> {
        Into::<crate::msgs::MsgDataToVerify>::into(self).validate(env, nonce)
    }
}


