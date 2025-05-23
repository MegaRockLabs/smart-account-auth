use saa_common::{
    CredentialId,  
    AuthError, Binary, ToString, Verifiable,
    ensure
};

use saa_schema::saa_type;


#[saa_type]
pub struct Secp256k1 {
    pub pubkey:    Binary,
    pub message:   Binary,
    pub signature: Binary,
    pub hrp:       Option<String>
}


impl Verifiable for Secp256k1 {

    fn id(&self) -> CredentialId {
        self.pubkey.to_string()
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
        let res = saa_crypto::secp256k1_verify(
            &saa_crypto::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&self, api: &dyn saa_common::wasm::Api) -> Result<(), AuthError> {
        let res = api.secp256k1_verify(
            &saa_crypto::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }
}
