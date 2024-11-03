
use core::fmt::Debug;
use saa_schema::wasm_serde;

use crate::{ensure, AuthError, Binary, CredentialId, CredentialInfo};

#[cfg(feature = "cosmwasm")]
use cosmwasm_std::{CustomMsg, Storage, Env};


#[wasm_serde]
pub struct AuthPayload<E = Binary> {
    pub hrp: Option<String>,
    pub address: Option<String>,
    pub credential_id: Option<CredentialId>,
    pub extension: Option<E>
}


impl<E> AuthPayload<E> {

    pub fn validate(&self) -> Result<(), AuthError> {
        let error : &str = "Only one of the 'address' or 'hrp' can be provided";

        if self.hrp.is_some() {
            ensure!(
                self.address.is_none(),
                AuthError::generic(error)
            );
        }
        if self.address.is_some() {
            ensure!(self.hrp.is_none(), AuthError::generic(error));
            let addr = self.address.clone().unwrap();
            ensure!(
                addr.len() > 3 && (addr.starts_with("0x") || addr.contains("1")),
                AuthError::generic("Invalid address")
            );
        }
        Ok(())
    }

    #[cfg(feature = "cosmwasm")]
    pub fn validate_cosmwasm(
        &self, 
        #[cfg(feature = "storage")]
        store: &dyn Storage
    ) -> Result<(), AuthError> {
        self.validate()?;
        #[cfg(feature = "storage")]
        if self.credential_id.is_some() {
            let info_res = crate::storage::CREDENTIAL_INFOS.load(
                store, self.credential_id.clone().unwrap()
            );
            ensure!(info_res.is_ok(), AuthError::NotFound);
            if self.hrp.is_some() {
                let name = info_res.unwrap().name;
                ensure!(
                    name == crate::CredentialName::CosmosArbitrary || name == crate::CredentialName::Secp256k1,
                    AuthError::generic("'hrp' can only be passed for 'cosmos-arbitrary' or 'secp256k1'")
                );
            }
        }
        Ok(())
    }
    
}


#[wasm_serde]
pub struct MsgDataToSign<M = ()> {
    pub chain_id: String,
    pub contract_address: String,
    #[cfg_attr(feature = "cosmwasm", serde(skip_deserializing))]
    pub messages: Vec<M>,
    pub nonce: String,
}

#[cfg(feature = "cosmwasm")]
impl<M> MsgDataToSign<M> {
    pub fn validate_cosmwasm(
        &self, 
        #[cfg(feature = "storage")]
        store: &dyn Storage, 
        env: &Env
    ) -> Result<(), AuthError> {
        ensure!(self.chain_id == env.block.chain_id, AuthError::ChainIdMismatch);
        ensure!(self.contract_address == env.contract.address, AuthError::ContractMismatch);
        ensure!(self.nonce.len() > 0, AuthError::MissingData("Nonce".to_string()));
        #[cfg(feature = "storage")]
        ensure!(!crate::storage::NONCES.has(store, &self.nonce), AuthError::DifferentNonce);
        Ok(())
    }
}

#[wasm_serde]
pub struct SignedDataMsg {
    pub data: Binary,
    pub signature: Binary,
    pub payload: Option<AuthPayload>,
}

#[cfg(feature = "cosmwasm")]
impl SignedDataMsg {
    pub fn validate_cosmwasm<M : serde::de::DeserializeOwned + std::default::Default>(
        &self,
        #[cfg(feature = "storage")]
        store: &dyn Storage,
        env: &Env
    ) -> Result<MsgDataToSign<M>, AuthError> {
        let msg : MsgDataToSign<M> = crate::from_json(&self.data)?;
        msg.validate_cosmwasm(
            #[cfg(feature = "storage")]
            store,
            env
        )?;
        Ok(msg)
    }
}



#[wasm_serde]
pub struct AccountCredentials {
    pub credentials: Vec<(Binary, CredentialInfo)>,
    pub verifying_id: Binary,
    pub native_caller: bool,
}



#[cfg(feature = "cosmwasm")]
impl CustomMsg for SignedDataMsg {}