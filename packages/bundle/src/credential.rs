use saa_common::{Verifiable, AuthError, CredentialId};
use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1};
use saa_custom::{caller::Caller, cosmos::arbitrary::CosmosArbitrary, evm::EvmCredential};
use saa_schema::wasm_serde;


#[wasm_serde]
pub enum Credential {
    Caller(Caller),
    Evm(EvmCredential),
    Secp256k1(Secp256k1),
    Ed25519(Ed25519),
    CosmosArbitrary(CosmosArbitrary)
}


impl Credential {
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
}

pub type Credentials = Vec<Credential>;