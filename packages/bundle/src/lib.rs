pub use saa_common::{Verifiable, AuthError, CredentialId};
pub use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1};
pub use saa_custom::{caller::Caller, cosmos::arbitrary::CosmosArbitrary, evm::EvmCredential};
pub use saa_schema::*;

// use cosmwasm_schema::cw_serde;

#[wasm_serde]
pub enum Credential {
    Caller(Caller),
    Evm(EvmCredential),
    Secp256k1(Secp256k1),
    Ed25519(Ed25519),
    CosmosArbitrary(CosmosArbitrary)
}

impl Credential {
    fn name(&self) -> &'static str {
        match self {
            Credential::Caller(_) => "caller",
            Credential::Evm(_) => "evm",
            Credential::Secp256k1(_) => "secp256k1",
            Credential::Ed25519(_) => "ed25519",
            Credential::CosmosArbitrary(_) => "cosmos-arbitrary"
        }
    }

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




#[wasm_serde]
pub struct CredentialData {
    pub credentials: Credentials,
    pub primary_index: Option<u8>
}

impl CredentialData {
    pub fn new(
        credentials: Credentials, 
        primary_index: Option<u8>
    ) -> Self {
        Self { 
            credentials, 
            primary_index 
        }
    }

    pub fn primary(&self) -> Credential {
        if self.primary_index.is_some() {
            return self.credentials[self.primary_index.unwrap() as usize].clone();
        } else {
            self.credentials.first().unwrap().clone()
        }
    }

    pub fn secondaries(&self) -> Credentials {
        if self.primary_index.is_some() {
            self.credentials
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != self.primary_index.unwrap() as usize)
                .map(|(_, c)| c.clone())
                .collect()
        } else {
            match self.credentials.len() {
                0 => return vec![],
                1 => return vec![],
                _ => self.credentials.iter().skip(1).map(|c| c.clone()).collect()
                
            }
        }
    }

    pub fn ids(&self) -> Vec<CredentialId> {
        self.credentials.iter().map(|c| c.id()).collect()
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.credentials.iter().map(|c| c.name()).collect()
    }

    pub fn values(&self) -> Vec<&dyn Verifiable> {
        self.credentials.iter().map(|c| c.value()).collect()
    }
}


impl Default for CredentialData {
    fn default() -> Self {
        Self { 
            credentials: vec![], 
            primary_index: None 
        }
    }
}

impl Verifiable for CredentialData {
    fn id(&self) -> CredentialId {
        self.primary().id()
    }

    fn validate(&self) -> Result<(), AuthError> {
        if self.credentials.len() == 0 {
            return Err(AuthError::NoCredentials);
        }
        if let Some(index) = self.primary_index {
            if index as usize >= self.credentials.len() {
                return Err(AuthError::Generic(format!("Primary index {} is out of bounds", index)));
            }
        }
        
        self.credentials.iter().map(|c| c.validate()).collect()
    }

    fn verify(&self) -> Result<(), AuthError> {
        self.validate()?;
        self.credentials.iter().map(|c| c.verify()).collect()

    }

    #[cfg(feature = "cosmwasm")]
    fn verify_api_cosmwasm(&self, api: &dyn saa_common::Api, env: &saa_common::Env) -> Result<(), AuthError> {
        self.validate()?;
        self.credentials.iter().map(|c| c.verify_api_cosmwasm(api, env)).collect()
    }
}