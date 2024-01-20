mod errors;
pub mod hashes;
pub use errors::*;
pub type CredentialId = Vec<u8>;
pub use cosmwasm_crypto;

#[cfg(feature = "cosmwasm")]
pub use cosmwasm_std::{
    Api, Env, Binary, Addr, CanonicalAddr, MessageInfo,
    from_json, to_json_binary,
};
#[cfg(feature = "substrate")]
pub use ink::primitives::{AccountId, Hash};


pub trait Verifiable {
    fn id(&self) -> CredentialId;
    fn validate(&self) -> Result<(), AuthError>;
    fn verify(&self) -> Result<(), AuthError>;


    #[cfg(feature = "cosmwasm")]
    fn verify_api_cosmwasm(&self, api: &dyn Api, env: &Env) -> Result<(), AuthError>;
}