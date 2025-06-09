/* #[cfg(feature = "types")]
pub use saa_common::wasm as cosmwasm_std;
#[cfg(feature = "replay")]
use {
    saa_common::{ensure, wasm::Env, ReplayError},
    crate::msgs::MsgDataToSign,
};


/* 


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






#[cfg(feature = "wasm")]
impl<M : Serialize> MsgDataToSign<M> {
    pub fn new_binary(
        &self,
        env: &saa_common::wasm::Env,
        nonce: Uint64,
        messages: Vec<M>
    ) -> Result<saa_common::Binary, saa_common::ReplayError> {
        use saa_common::to_json_binary;
        let chain_id = env.block.chain_id.clone();
        let contract_address = env.contract.address.to_string();
        ensure!(chain_id == self.chain_id, ReplayError::ChainIdMismatch);
        ensure!(contract_address == self.contract_address, ReplayError::ContractMismatch);
        ensure!(nonce == self.nonce, ReplayError::InvalidNonce(nonce.u64()));
        to_json_binary(&MsgDataToSign{
            chain_id: env.block.chain_id.clone(),
            contract_address: env.contract.address.to_string(),
            messages,
            nonce,
        }).map_err(|_| ReplayError::ToBin("MsgDataToSign".to_string()))
    }
    
}
 */


#[cfg(feature = "replay")]
impl<M : serde::Serialize> MsgDataToSign<M> {
    pub fn new_binary(
        env: &saa_common::wasm::Env,
        nonce: saa_common::Uint64,
        messages: Vec<M>
    ) -> Result<saa_common::Binary, saa_common::ReplayError> {
        saa_common::to_json_binary(&Self{
            chain_id: env.block.chain_id.clone(),
            contract_address: env.contract.address.to_string(),
            messages,
            nonce,
        }).map_err(|_| ReplayError::ToBin("MsgDataToSign".to_string()))
    }
}

#[cfg(feature = "replay")]
impl crate::msgs::MsgDataToVerify {
    pub fn validate(&self, env: &Env, expected: u64 ) -> Result<(), ReplayError> {
        ensure!(self.chain_id == env.block.chain_id, ReplayError::ChainIdMismatch);
        ensure!(self.contract_address == env.contract.address.to_string(), ReplayError::ContractMismatch);
        let signed = self.nonce.u64();
        ensure!(signed == expected, ReplayError::InvalidNonce(expected));
        Ok(())
    }
}


#[cfg(feature = "replay")]
impl<M : serde::de::DeserializeOwned + serde::Serialize> crate::msgs::MsgDataToSign<M> {
    pub fn validate(&self, env: &Env, nonce: u64) -> Result<(), ReplayError> {
        Into::<crate::msgs::MsgDataToVerify>::into(self).validate(env, nonce)
    }
}


} 
*/

impl From<&saa_common::wasm::MessageInfo> for crate::Caller {
    fn from(info: &saa_common::wasm::MessageInfo) -> Self {
        crate::Caller(info.sender.to_string())
    }
}