#![cfg_attr(not(feature = "std"), no_std)]


mod binary;
mod errors;
mod identity;
pub mod utils;
pub mod storage;
pub mod messages;
pub mod hashes;
pub use errors::*;
pub use binary::{Binary, to_json_binary, from_json};
use saa_schema::wasm_serde;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;


#[cfg(feature = "std")]
pub use std::{
    string::{ToString, String},
    vec, vec::Vec, 
    format
};

#[cfg(not(feature = "std"))]
pub use ink::prelude::{
    string::{ToString, String},
    vec, vec::Vec, 
    format, 
};



#[cfg(feature = "native")]
pub mod crypto {
    pub use cosmwasm_crypto::*;    
} 



#[cfg(feature = "cosmwasm")]
pub mod cosmwasm {
    pub use cosmwasm_std::{
        Api, Env, Addr, CanonicalAddr, MessageInfo, Binary, Storage,
        from_json, to_json_binary, ensure, ensure_eq, ensure_ne
    };
}


#[cfg(feature = "substrate")]
pub mod substrate {
    pub use ink::env as ink_env;
    pub use {
        ink_env::Environment as InkEnvironment,
        ink::EnvAccess as InkApi,
    };

    pub mod default {
        use ink::env as ink_env;
        pub use ink_env::DefaultEnvironment;
        pub type AccountId = <DefaultEnvironment as ink_env::Environment>::AccountId;
        pub type EnvAccess<'a> = ink::EnvAccess<'a, DefaultEnvironment>;
    }
}

#[cfg(feature = "cosmwasm")]
use cosmwasm::*;
#[cfg(feature = "substrate")]
use substrate::*;
#[cfg(feature = "storage")]
use crate::{storage::*, messages::*};


#[macro_export]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            return Err(core::convert::From::from($e));
        }
    };
}




pub trait Verifiable  {

    fn id(&self) -> CredentialId;

    fn human_id(&self) -> String {
        Binary(self.id()).to_base64()
    }

    fn info(&self) -> CredentialInfo;

    fn message(&self) -> Binary;

    fn message_digest(&self) -> Result<Vec<u8>, AuthError> {
        Ok(hashes::sha256(&self.message()))
    }


    fn is_cosmos_derivable(&self) -> bool {
        let name = self.info().name;
        let ok = name == CredentialName::CosmosArbitrary ||
                            name == CredentialName::Secp256k1 ||
                            name == CredentialName::Caller;

        #[cfg(feature = "injective")]
        let ok = ok || (name == CredentialName::EthPersonalSign);
        ok
    }


    fn validate(&self) -> Result<(), AuthError>;


    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError>;


    #[cfg(feature = "substrate")]
    fn verify_ink<'a>(&self,  _ : InkApi<'a, impl InkEnvironment>) -> Result<(), AuthError> {
        #[cfg(feature = "native")]
        if true {
            self.verify()?;
            return Ok(());
        } 
        Err(AuthError::generic("Not implemented"))
    }



    #[cfg(feature = "cosmwasm")]
    fn cosmos_address(&self, api: &dyn Api) -> Result<Addr, AuthError> {
        Ok(match self.info().hrp {
            Some(hrp) => Addr::unchecked(utils::pubkey_to_address(&self.id(), &hrp)?),
            None => {
                let canon = utils::pubkey_to_canonical(&self.id());
                let addr = api.addr_humanize(&canon)?;
                addr
            }
        })
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(
        &self, 
        _:  &dyn Api, 
        _:  &Env, 
    ) -> Result<(), AuthError> {   
        #[cfg(feature = "native")]
        if true {
            self.verify()?;
            return Ok(());
        } 
        Err(AuthError::generic("Not Implemented"))
    }


    #[cfg(all(feature = "cosmwasm", feature = "storage"))]
    fn assert_query_cosmwasm<D>(
        &self, 
        api     :  &dyn Api, 
        storage :  &dyn Storage,
        env     :  &Env, 
        _       :  &Option<MessageInfo>
    ) -> Result<String, AuthError> 
        where D: schemars::JsonSchema + serde::de::DeserializeOwned
    {   
        ensure!(CREDENTIAL_INFOS.has(storage, self.id()), AuthError::NotFound);
        self.verify_cosmwasm(api, env)?;

        #[cfg(feature = "replay")]
        if true {
            let signed : SignedData<D> = from_json(&self.message()).unwrap(); 
            signed.validate_cosmwasm(storage, env)?;
            let nonce = signed.data.nonce.clone();
            ensure!(!NONCES.has(storage, &nonce), AuthError::NonceUsed);
            return Ok(nonce)
        }
        Ok(String::default())
    }


    #[cfg(all(feature = "cosmwasm", feature = "storage"))]
    fn assert_execute_cosmwasm<D>(
        &self, 
        api     :  &dyn Api,
        #[cfg(feature = "replay")]
        storage :  &mut dyn Storage,
        #[cfg(not(feature = "replay"))]
        storage :  &dyn Storage,
        env     :  &Env, 
        info    :  &Option<MessageInfo>
    ) -> Result<(), AuthError> 
        where D: schemars::JsonSchema + serde::de::DeserializeOwned
    {
        let nonce = self.assert_query_cosmwasm::<D>(api, storage, env, info)?;
        if !nonce.is_empty() {
            NONCES.save(storage, &nonce, &true)?;
        }
        Ok(())
    }


    #[cfg(all(feature = "cosmwasm", feature = "storage"))]
    fn save_cosmwasm<D>(
        &self, 
        api: &dyn Api, 
        storage: &mut dyn Storage,
        env: &Env, 
        info: &Option<MessageInfo>
    ) -> Result<Self, AuthError> 
        where Self : Clone, D: JsonSchema + DeserializeOwned
    {
        CREDENTIAL_INFOS.save(storage, self.id(), &self.info())?;

        #[cfg(feature = "replay")]
        if true {
            self.assert_execute_cosmwasm::<D>(api, storage, env, info)?;
            return Ok(self.clone());
        } 

        self.verify_cosmwasm(api, env)?;
        Ok(self.clone())
    }



}


pub type CredentialId = Vec<u8>;


#[wasm_serde]
pub enum CredentialName {
    Caller,
    CosmosArbitrary,
    EthPersonalSign,
    Passkey,
    Secp256k1,
    Secp256r1,
    Ed25519,
}


#[wasm_serde]
pub struct CredentialInfo<E : JsonSchema = Binary> {
    /// name of the used credential
    pub name: CredentialName,
    /// human readable prefix to encode from a public key
    pub hrp: Option<String>,
    /// extension data
    pub extension: Option<E>,
}
