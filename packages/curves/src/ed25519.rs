use saa_schema::saa_type;
use saa_common::{
    CredentialId, 
    AuthError, Binary, ToString, Verifiable, ensure
};


#[saa_type]
pub struct Ed25519 {
    pub pubkey:    Binary,
    pub message:   Binary,
    pub signature: Binary,
}


impl Verifiable for Ed25519 {

    fn id(&self) -> CredentialId {
        self.pubkey.to_string()
    }

    fn validate(&self) -> Result<(), AuthError> {
        ensure!(
            self.signature.len() > 0 &&
                self.message.len() > 0 && 
                self.pubkey.len() > 0,
            AuthError::MissingData("Empty credential data".to_string())
        );
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        let success = saa_crypto::ed25519_verify(
            &saa_crypto::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(success, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&self, api: &dyn saa_common::wasm::Api) -> Result<(), AuthError> 
        where Self: Clone
    {
        let success = api.ed25519_verify(
            &saa_crypto::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(success, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }

}