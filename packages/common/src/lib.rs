mod inner;
mod errors;
mod digest;
pub mod hashes;
pub mod crypto;

pub use errors::*;
pub type CredentialId = Vec<u8>;

#[cfg(feature = "cosmwasm")]
pub use cosmwasm_std::{
    Api, Env, Binary, Addr, CanonicalAddr, MessageInfo,
    from_json, to_json_binary,
};


#[cfg(feature = "substrate")]
pub mod substrate {
    #![cfg_attr(not(feature = "std"), no_std)]
    pub use {
        ink::env as ink_env,
        ink::env::Environment as InkEnvironment,
        ink::EnvAccess as InkApi,
    };
    pub mod ink_default {
        use ink::env::Environment;
        use ink::env::DefaultEnvironment;
    
        pub type AccountId = <DefaultEnvironment as Environment>::AccountId;
        pub type EnvAccess<'a> = ink::EnvAccess<'a, DefaultEnvironment>;
    }

}
#[cfg(feature = "substrate")]
pub use substrate::*;


pub trait Verifiable  {

    fn id(&self) -> CredentialId;
    fn validate(&self) -> Result<(), AuthError>;
    fn verify(&self) -> Result<(), AuthError>;


    #[cfg(feature = "substrate")]
    fn verified_ink<'a>(&self,  _ : InkApi<'a, impl InkEnvironment + Clone>) -> Result<Self, AuthError> 
        where Self: Clone
    {
        self.verify()?;
        Ok(self.clone())
    }

    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(& self, _:  &dyn Api, _:  &Env, _: &MessageInfo) -> Result<Self, AuthError> 
        where Self: Clone
    {
        self.verify()?;
        Ok(self.clone())
    }
}


