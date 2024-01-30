#[cfg(feature = "cosmwasm")]
use {
    saa_common::{Api, Env, MessageInfo}, 
    saa_custom::cosmos::arbitrary::CosmosArbitrary
};

#[cfg(feature = "substrate")]
use saa_common::Vec;


use saa_common::{
    AuthError, Verifiable, CredentialId,
    crypto::secp256k1_verify,
    hashes::sha256
};

use saa_schema::wasm_serde;


#[wasm_serde]
pub struct Secp256k1 {
    pub pubkey:    Vec<u8>,
    pub message:   Vec<u8>,
    pub signature: Vec<u8>,
}


#[cfg(feature = "cosmwasm")]
impl From<Secp256k1> for CosmosArbitrary {
    fn from(v: Secp256k1) -> Self {
        Self {
            pubkey:    v.pubkey,
            message:   v.message,
            signature: v.signature,
            hrp:       None
        }
    }
}

impl Verifiable for Secp256k1 {

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
        secp256k1_verify(
            &sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(&self, api: &dyn Api, env: &Env, info: &MessageInfo) -> Result<Self, AuthError> {

        let hash = sha256(&self.message);

        match api.secp256k1_verify(&hash, &self.signature, &self.pubkey) {
            Ok(status) => {
                if status {
                    return Ok(self.clone());
                }
            },
            Err(_) => {},
        }

        CosmosArbitrary::from(self.clone()).verified_cosmwasm(api, env, info)?;
        Ok(self.clone())
    }
}
