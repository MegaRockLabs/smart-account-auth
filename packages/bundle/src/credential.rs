use core::fmt::Display;

use saa_common::{Verifiable, AuthError, CredentialId};
use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1};
use saa_custom::{caller::Caller, cosmos::arbitrary::CosmosArbitrary, evm::EvmCredential};
use saa_schema::wasm_serde;

#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm;

#[wasm_serde]
pub enum Credential<M: Display + Clone = String> {
    Caller(Caller),
    Evm(EvmCredential),
    Secp256k1(Secp256k1),
    Ed25519(Ed25519),
    CosmosArbitrary(CosmosArbitrary<M>)
}


impl<M: Display + Clone>  Credential<M> {
    pub fn name(&self) -> &'static str {
        match self {
            Credential::Caller(_) => "caller",
            Credential::Evm(_) => "evm",
            Credential::Secp256k1(_) => "secp256k1",
            Credential::Ed25519(_) => "ed25519",
            Credential::CosmosArbitrary(_) => "cosmos-arbitrary"
        }
    }

    pub fn value(&self) -> &dyn Verifiable {
        match self {
            Credential::Caller(c) => c,
            Credential::Evm(c) => c,
            Credential::Secp256k1(c) => c,
            Credential::Ed25519(c) => c,
            Credential::CosmosArbitrary(c) => c
        }
    }
    
}

impl<M: Display + Clone> Verifiable for Credential<M> {

    fn id(&self) -> CredentialId {
        self.value().id()
    }

    fn validate(&self) -> Result<(), AuthError> {
        self.value().validate()
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.validate()?;
        self.value().verify()
    }

    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(& self, api:  &dyn cosmwasm::Api, env:  &cosmwasm::Env, info: &Option<cosmwasm::MessageInfo>) -> Result<Self, AuthError> 
        where Self: Clone
    {
        self.validate()?;
        Ok(match self {
            Credential::Caller(c) => Credential::Caller(c.verified_cosmwasm(api, env, info)?),
            Credential::Evm(c) => Credential::Evm(c.verified_cosmwasm(api, env, info)?),
            Credential::Secp256k1(c) => Credential::Secp256k1(c.verified_cosmwasm(api, env, info)?),
            Credential::Ed25519(c) => Credential::Ed25519(c.verified_cosmwasm(api, env, info)?),
            Credential::CosmosArbitrary(c) => Credential::CosmosArbitrary(c.verified_cosmwasm(api, env, info)?)
        })
    }

}

pub type Credentials = saa_common::Vec<Credential>;