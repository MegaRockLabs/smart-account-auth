#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::Api;

use saa_common::{
    ensure, hashes::sha256, utils::pubkey_to_address, AuthError, Binary, 
    CredentialId, String, ToString, Verifiable
};

use super::utils::preamble_msg_arb_036;
use saa_schema::wasm_serde;


#[wasm_serde]
pub struct CosmosArbitrary {
    pub pubkey:    Binary,
    pub signature: Binary,
    pub message:   Binary,
    pub hrp:       Option<String>
}

impl CosmosArbitrary {

    fn message_digest(&self) -> Result<Vec<u8>, AuthError> {
        ensure!(self.hrp.is_some(), AuthError::Generic("Must provide prefix for the public key".to_string()));
        Ok(sha256(&preamble_msg_arb_036(
            pubkey_to_address(&self.pubkey, self.hrp.as_ref().unwrap())?.as_str(),
            &self.message.to_string()
        ).as_bytes()))
    }
}


impl Verifiable for CosmosArbitrary {

    fn id(&self) -> CredentialId {
        self.pubkey.to_vec()
    }

    fn hrp(&self) -> Option<String> {
        self.hrp.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        if !(self.signature.len() > 0 &&
            self.message.to_string().len() > 0 && 
            self.pubkey.len() > 0) {
            return Err(AuthError::MissingData("Empty credential data".to_string()));
        }
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        let success = saa_common::crypto::secp256k1_verify(
            &self.message_digest()?,
            &self.signature,
            &self.pubkey
        )?;
        ensure!(success, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(
        &self, 
        api:  &dyn Api
    ) -> Result<(), AuthError> {
        let success = api.secp256k1_verify(
            &self.message_digest()?,
            &self.signature,
            &self.pubkey
        )?;
        ensure!(success, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }

}