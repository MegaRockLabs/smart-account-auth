use crate::errors::AuthError;

pub type CredentialId = Vec<u8>;

#[cfg(feature = "cosmwasm")]
use cosmwasm_std::Api;

// use saa_macros::wasm_serde;
use ink;

#[cfg_attr(feature = "substrate", ink::trait_definition)] 
pub trait Credential {

    #[cfg_attr(feature = "substrate", ink(message))] 
    fn id(&self) -> CredentialId;
    #[cfg_attr(feature = "substrate", ink(message))] 
    fn validate(&self) -> Result<(), AuthError>;
    #[cfg_attr(feature = "substrate", ink(message))] 
    fn verify(&self) -> Result<(), AuthError>;
    #[cfg(feature = "cosmwasm")]
    fn verify_api_cosmwasm(&self, api: &dyn Api) -> Result<(), AuthError>;
}


pub struct CredentialData {
    pub credentials: Box<dyn Credential>,
}
