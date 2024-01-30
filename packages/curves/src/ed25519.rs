#[cfg(feature = "cosmwasm")]
use saa_common::{Api, Env, MessageInfo};

use saa_common::{
    AuthError, Verifiable, CredentialId,
    crypto::ed25519_verify,
    hashes::sha256
};

use saa_schema::wasm_serde;



#[wasm_serde]
pub struct Ed25519 {
    pub pubkey:    Vec<u8>,
    pub message:   Vec<u8>,
    pub signature: Vec<u8>,
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
        let res = ed25519_verify(
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
    fn verified_cosmwasm(&self, api: &dyn Api, _: &Env, _: &MessageInfo) -> Result<Self, AuthError> {
        let res = api.ed25519_verify(
            &sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        if !res {
            return Err(AuthError::Signature("Signature verification failed".to_string()));
        }
        Ok(self.clone())
    }
}