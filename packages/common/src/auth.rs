use crate::errors::AuthError;

pub type CredentialId = Vec<u8>;

#[cfg(feature = "cosmwasm")]
use cosmwasm_std::Api;

use saa_macros::wasm_serde;


pub trait Credential {
    fn id(&self) -> CredentialId;
    fn validate(&self) -> Result<(), AuthError>;
    fn verify(&self) -> Result<(), AuthError>;

    #[cfg(feature = "cosmwasm")]
    fn verify_api_cosmwasm(&self, api: &dyn Api) -> Result<(), AuthError>;
}



#[cfg_attr(feature = "cosmwasm", 
    derive(
        saa_macros::cosmwasm_schema::serde::Serialize,
        saa_macros::cosmwasm_schema::serde::Deserialize,
        saa_macros::cosmwasm_schema::schemars::JsonSchema
    ),
    saa_macros::cosmwasm_schema::serde(deny_unknown_fields)
)]
#[cfg_attr(feature = "solana", derive(
    saa_macros::borsh::derive::BorshSerialize, 
    saa_macros::borsh::derive::BorshDeserialize
))]
#[cfg_attr(feature = "substrate", derive(
    saa_macros::scale::Encode, 
    saa_macros::scale::Decode, 
    saa_macros::scale_info::TypeInfo)
)]
pub struct CredentialData {
    pub credentials: Box<dyn Credential>,
}
