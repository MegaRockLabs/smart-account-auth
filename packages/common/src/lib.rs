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
pub use ink::{
    env::{
        account_id, caller,
        Environment, DefaultEnvironment
    },
    primitives::AccountId
};



#[cfg(not(feature = "substrate"))]
pub trait Verifiable {
    fn id(&self) -> CredentialId;
    fn validate(&self) -> Result<(), AuthError>;
    fn verify(&self) -> Result<(), AuthError>;


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&mut self, _:  &dyn Api, _:  &Env, _: &MessageInfo) -> Result<(), AuthError> {
        self.verify()
    }
}


#[cfg(feature = "substrate")]
pub trait Verifiable<InkEnv: Environment = DefaultEnvironment> {
    fn id(&self) -> CredentialId;
    fn validate(&self) -> Result<(), AuthError>;
    fn verify(&self) -> Result<(), AuthError>;

    #[cfg(feature = "substrate")]
    fn verify_ink(&mut self) -> Result<(), AuthError> {
        self.verify()
    }

    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&mut self, _:  &dyn Api, _:  &Env, _: &MessageInfo) -> Result<(), AuthError> {
        self.verify()
    }
}
