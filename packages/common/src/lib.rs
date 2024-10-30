#![cfg_attr(not(feature = "std"), no_std)]


mod binary;
mod errors;
mod identity;
pub mod utils;
pub mod storage;
pub mod messages;
pub mod hashes;
pub mod constants;
pub use errors::*;
pub use binary::{Binary, to_json_binary, from_json};
use saa_schema::wasm_serde;
use serde::Serialize;
use constants::{IS_INJECTIVE, IS_REPLAY_PROTECTION_ON};


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



#[macro_export]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            return Err(core::convert::From::from($e));
        }
    };
}




pub trait Verifiable   {

    fn validate(&self) -> Result<(), AuthError>;

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
        name == CredentialName::CosmosArbitrary ||
        name == CredentialName::Secp256k1 ||
        name == CredentialName::Caller ||
            (IS_INJECTIVE && name == CredentialName::EthPersonalSign)
    }


    #[cfg(all(feature = "cosmwasm", feature = "replay"))]
    fn validate_signed_data(&self, storage: &dyn cosmwasm_std::Storage, env: &cosmwasm_std::Env) -> Result<String, AuthError> {
        self.validate()?;
        let signed : messages::SignedData<cosmwasm_std::Empty> = from_json(&self.message()).unwrap(); 
        let data = signed.data.clone();
        ensure_eq!(env.block.chain_id, data.chain_id, AuthError::ChainIdMismatch);
        ensure_eq!(env.contract.address, data.contract_address, AuthError::ContractMismatch);
        ensure!(data.nonce.len() > 0, AuthError::MissingData("Nonce".to_string()));
        ensure!(storage::NONCES.has(storage, data.nonce.clone()), AuthError::NonceUsed);
        Ok(data.nonce)
    }


    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError>;



    #[cfg(feature = "substrate")]
    fn verified_ink<'a>(&self,  _ : InkApi<'a, impl InkEnvironment + Clone>) -> Result<Self, AuthError> 
        where Self: Clone
    {
        #[cfg(feature = "native")]
        if true {
            self.verify()?;
            return Ok(self.clone());
        } 
        Err(AuthError::generic("Not implemented"))
    }

    
    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(& self, _:  &dyn Api, _:  &Env, _: &Option<MessageInfo>) -> Result<Self, AuthError> 
        where Self: Clone
    {   
        #[cfg(feature = "native")]
        if true {
            self.verify()?;
            return Ok(self.clone());
        } 
        
        Err(AuthError::generic("Not Implemented"))
    }


    #[cfg(feature = "cosmwasm")]
    fn cosmos_address(&self, api: &dyn Api) -> Result<Addr, AuthError> {
        match self.info().hrp {
            Some(hrp) => utils::pubkey_to_address(&self.id(), &hrp),
            None => {
                let canon = utils::pubkey_to_canonical(&self.id());
                let addr = api.addr_humanize(&canon)?;
                Ok(addr)
            }
        }
    }


    #[cfg(all(feature = "cosmwasm", feature = "storage"))]
    fn verify_and_save(
        &self, 
        api: &dyn Api, 
        storage: &mut dyn Storage,
        env: &Env, 
        info: &Option<MessageInfo>
    ) -> Result<Self, AuthError> 
        where Self: Clone
    {
        use storage::*;
        let verified = self.verified_cosmwasm(api, env, info)?;
        if IS_REPLAY_PROTECTION_ON {
            let nonce = self.validate_signed_data(storage, env)?;
            NONCES.save(storage, nonce, &true)?;
        }
        if verified.info().name != CredentialName::Caller {
            VERIFYING_CRED_ID.save(storage, &verified.id())?;
        }
        CREDENTIAL_INFOS.save(storage, verified.id(), &verified.info())?;
        Ok(verified)
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
pub struct CredentialInfo<E : Serialize + Clone = Binary> {
    /// name of the used credential
    pub name: CredentialName,
    pub hrp: Option<String>,
    pub extension: Option<E>,
}
