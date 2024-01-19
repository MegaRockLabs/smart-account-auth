pub use saa_common::{Verifiable, AuthError, CredentialId};
pub use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1};
pub use saa_custom::{caller::Caller, cosmos::arbitrary::CosmosArbitrary, evm::EvmCredential};
pub use saa_schema::*;

#[wasm_serde]
pub enum Credential {
    Caller(Caller),
    Evm(EvmCredential),
    Secp256k1(Secp256k1),
    Ed25519(Ed25519),
    CosmosArbitrary(CosmosArbitrary)
}

impl Credential {
    fn value(&self) -> &dyn Verifiable {
        match self {
            Credential::Caller(c) => c,
            Credential::Evm(c) => c,
            Credential::Secp256k1(c) => c,
            Credential::Ed25519(c) => c,
            Credential::CosmosArbitrary(c) => c
        }
    } 
}

impl Verifiable for Credential {

    fn id(&self) -> CredentialId {
        self.value().id()
    }

    fn validate(&self) -> Result<(), AuthError> {
        self.value().validate()
    }

    fn verify(&self) -> Result<(), AuthError> {
        self.validate()?;
        self.value().verify()
    }

    #[cfg(feature = "cosmwasm")]
    fn verify_api_cosmwasm(&self, api: &dyn saa_common::Api, env: &saa_common::Env) -> Result<(), AuthError> {
        self.validate()?;
        self.value().verify_api_cosmwasm(api, env)
    }
}

pub type Credentials = Vec<Credential>;