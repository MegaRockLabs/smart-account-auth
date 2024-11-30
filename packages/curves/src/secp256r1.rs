#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::Api;

use saa_schema::wasm_serde;

use saa_common::{
    CredentialId, 
    AuthError,  Binary,  ToString, Verifiable, ensure
};


#[wasm_serde]
pub struct Secp256r1 {
    pub pubkey:    Binary,
    pub message:   Binary,
    pub signature: Binary,
}



impl Verifiable for Secp256r1 {

    fn id(&self) -> CredentialId {
        self.pubkey.to_vec()
    }

    fn validate(&self) -> Result<(), AuthError> {
        ensure!(self.signature.len() > 0 &&
                self.message.len() > 0 && 
                self.pubkey.len() > 0,
            AuthError::MissingData("Empty credential data".to_string())
        );
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        let res = saa_common::crypto::secp256r1_verify(
            &saa_common::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&self, api : &dyn Api) -> Result<(), AuthError> {
        let res = api.secp256r1_verify(
            &saa_common::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }
}
