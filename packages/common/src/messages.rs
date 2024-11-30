
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
pub struct MsgDataToSign<M = String> {
    pub chain_id: String,
    pub contract_address: String,
    pub messages: Vec<M>,
    pub nonce: String,
}


#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "cosmwasm", derive(
    ::saa_schema::serde::Serialize,
    ::saa_schema::serde::Deserialize,
    ::saa_schema::schemars::JsonSchema
), schemars(crate = "::saa_schema::schemars"
))]
#[cfg_attr(feature = "substrate", derive(
    ::saa_schema::scale::Encode, ::saa_schema::scale::Decode
))]
#[cfg_attr(feature = "solana", derive(
    ::saa_schema::borsh::BorshSerialize, ::saa_schema::borsh::BorshDeserialize
))]
#[cfg_attr(all(feature = "std", feature="substrate"), derive(saa_schema::scale_info::TypeInfo))]
#[allow(clippy::derive_partial_eq_without_eq)]
pub struct MsgDataToVerify {
    pub chain_id: String,
    pub contract_address: String,
    pub nonce: String,
}


impl<M> Into<MsgDataToVerify> for &MsgDataToSign<M> {
    fn into(self) -> MsgDataToVerify {
        MsgDataToVerify {
            chain_id: self.chain_id.clone(),
            contract_address: self.contract_address.clone(),
            nonce: self.nonce.clone(),
        }
    }
}


#[cfg(feature = "cosmwasm")]
impl MsgDataToVerify {
    pub fn validate_cosmwasm(
        &self, 
        #[cfg(feature = "storage")]
        store: &dyn Storage, 
        env: &Env
    ) -> Result<(), AuthError> {
        ensure!(self.chain_id == env.block.chain_id, AuthError::ChainIdMismatch);
        ensure!(self.contract_address == env.contract.address.to_string(), AuthError::ContractMismatch);
        ensure!(self.nonce.len() > 0, AuthError::MissingData("Nonce".to_string()));
        #[cfg(feature = "storage")]
        ensure!(crate::storage::ACCOUNT_NUMBER.load(store)?.to_string() == self.nonce, AuthError::DifferentNonce);
        Ok(())
    }
}


#[cfg(feature = "cosmwasm")]
impl<M> MsgDataToSign<M> {
    pub fn validate_cosmwasm(
        &self, 
        #[cfg(feature = "storage")]
        store: &dyn Storage, 
        env: &Env
    ) -> Result<(), AuthError> {
        Into::<MsgDataToVerify>::into(self)
        .validate_cosmwasm(
            #[cfg(feature = "storage")]
            store,
            env
        )
    }
}

#[wasm_serde]
pub struct SignedDataMsg {
    pub data: Binary,
    pub signature: Binary,
    pub payload: Option<AuthPayload>,
}



#[wasm_serde]
pub struct AccountCredentials {
    pub credentials: Vec<(Binary, CredentialInfo)>,
    pub verifying_id: Binary,
    pub native_caller: bool,
}



#[cfg(feature = "cosmwasm")]
impl CustomMsg for SignedDataMsg {}