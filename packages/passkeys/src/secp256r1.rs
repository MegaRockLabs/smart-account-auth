use saa_common::{AuthError,  Binary,  ToString, Verifiable, ensure};


#[saa_schema::saa_type]
pub struct Secp256r1 {
    pub pubkey:    Binary,
    pub message:   Binary,
    pub signature: Binary,
}



impl Verifiable for Secp256r1 {

    fn id(&self) -> saa_common::CredentialId {
        self.pubkey.to_string()
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
        let res = saa_crypto::secp256r1_verify(
            &saa_crypto::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(
        &self,
        #[allow(unused_variables)]
        api : &dyn saa_common::wasm::Api
    ) -> Result<(), AuthError> {
        use saa_crypto::hashes::sha256;
        #[cfg(feature = "no_api_r1")]
        let res = saa_crypto::secp256r1_verify(
            &sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        #[cfg(not(feature = "no_api_r1"))]
        let res = api.secp256r1_verify(
            &sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }
}

