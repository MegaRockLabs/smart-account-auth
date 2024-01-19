#[cfg(feature = "cosmwasm")]
use {
    cosmwasm_std::{Api, Env}, 
    saa_custom::cosmos::arbitrary::CosmosArbitrary
};

use saa_common::{
    AuthError, Verifiable, CredentialId, 
    hashes::sha256
};

use saa_macros::wasm_serde;


#[wasm_serde]
pub struct Ed25519 {
    pub pubkey:    Vec<u8>,
    pub message:   Vec<u8>,
    pub signature: Vec<u8>,
}

#[cfg(feature = "cosmwasm")]
impl From<Ed25519> for CosmosArbitrary {
    fn from(v: &Ed25519) -> Self {
        Self {
            pubkey:    v.pubkey,
            message:   v.message,
            signature: v.signature,
            hrp:       None
        }
    }
}

impl Verifiable for Ed25519 {

    fn id(&self) -> CredentialId {
        self.pubkey.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        if !(self.signature.len() > 0 &&
            self.message.len() > 0 && 
            self.pubkey.len() > 0) {
            return Err(AuthError::InvalidLength("Empty credential data".to_string()));
        }
        Ok(())
    }

    fn verify(&self) -> Result<(), AuthError> {
        let res = cosmwasm_crypto::ed25519_verify(
            &sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        if !res {
            return Err(AuthError::Signature("Signature verification failed".to_string()));
        }
        Ok(())
    }

    #[cfg(feature = "cosmwasm")]
    fn verify_api_cosmwasm(&self, api: &dyn Api, _: &Env) -> Result<(), AuthError> {
        let res = api.ed25519_verify(
            &sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        if !res {
            return Err(AuthError::Signature("Signature verification failed".to_string()));
        }
        Ok(())
    }
}