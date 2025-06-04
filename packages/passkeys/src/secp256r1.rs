use saa_common::{ensure, AuthError, Binary, CredentialInfo, CredentialName, ToString, Verifiable};


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

    #[allow(unused_variables)]    
    #[cfg(any(feature = "cosmwasm", feature = "native"))]
    fn verify(&self,
        #[cfg(feature = "cosmwasm")]
        deps: saa_common::wasm::Deps
    ) -> Result<CredentialInfo, AuthError> {
        let res = true;
        #[cfg(all(any(feature = "native", feature = "no_api_r1"), not(feature = "cosmwasm")))]
        let res = saa_crypto::secp256r1_verify(
            &saa_crypto::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        #[cfg(all(feature = "cosmwasm", not(feature = "no_api_r1")))]
        let res = deps.api.secp256r1_verify(
            &saa_crypto::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        Ok(CredentialInfo {
            extension: None,
            address: None,
            hrp: None,
            name: CredentialName::Secp256r1,
        })
    }


}

