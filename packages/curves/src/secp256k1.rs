use saa_common::{
    CredentialId,  
    AuthError, Binary, ToString, Verifiable,
    ensure
};

use saa_schema::wasm_serde;


#[wasm_serde]
pub struct Secp256k1 {
    pub pubkey:    Binary,
    pub message:   Binary,
    pub signature: Binary,
    pub hrp:       Option<String>
}


impl Verifiable for Secp256k1 {

    fn id(&self) -> CredentialId {
        self.pubkey.to_vec()
    }

    fn hrp(&self) -> Option<String> {
        self.hrp.clone()
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
        let res = saa_common::crypto::secp256k1_verify(
            &saa_common::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }


    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self, api: &dyn saa_common::wasm::Api) -> Result<(), AuthError> {
        let res = api.secp256k1_verify(
            &saa_common::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }
}
