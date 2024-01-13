use crate::errors::AuthError;
pub type CredentialId = Vec<u8>;

#[cfg(feature = "cosmwasm")]
use cosmwasm_std::Api;

pub trait Credential {
    fn id(&self) -> CredentialId;
    fn validate(&self) -> Result<(), AuthError>;
    fn verify(&self) -> Result<(), AuthError>;

    #[cfg(feature = "cosmwasm")]
    fn verify_api_cosmwasm(&self, api: &dyn Api) -> Result<(), AuthError>;
}