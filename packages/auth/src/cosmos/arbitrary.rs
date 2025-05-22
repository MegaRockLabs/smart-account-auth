
use saa_common::{AuthError, Binary, CredentialId, String, ToString, Verifiable};


#[saa_schema::saa_type]
pub struct CosmosArbitrary {
    pub pubkey:    Binary,
    pub signature: Binary,
    pub message:   Binary,
    pub hrp:       Option<String>
    
}


#[cfg(any(feature = "cosmwasm", feature = "native"))]
impl CosmosArbitrary {
    fn message_digest(&self) -> Result<Vec<u8>, AuthError> {
        use saa_crypto::{hashes::sha256, pubkey_to_address};
        match self.hrp {
            Some(ref hrp) => Ok(
                sha256(
                    super::utils::preamble_msg_arb_036(
                        pubkey_to_address(&self.pubkey, hrp)?.as_str(),
                        &self.message.to_string()
                    ).as_bytes()
                )
            ),
            None => Err(AuthError::Generic("Must provide prefix for the public key".to_string()))
        }
    }
}


impl Verifiable for CosmosArbitrary {

    fn id(&self) -> CredentialId {
        self.pubkey.to_string()
    }

    fn hrp(&self) -> Option<String> {
        self.hrp.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        if !(self.signature.len() > 0 &&
            self.message.to_string().len() > 0 && 
            self.pubkey.len() > 0) {
            return Err(AuthError::MissingData("Missing credential data".to_string()));
        }
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        let success = saa_crypto::secp256k1_verify(
            &self.message_digest()?,
            &self.signature,
            &self.pubkey
        )?;
        saa_common::ensure!(success, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(
        &self, 
        api:  &dyn saa_common::wasm::Api
    ) -> Result<(), AuthError> {
        let success = api.secp256k1_verify(
            &self.message_digest()?,
            &self.signature,
            &self.pubkey
        )?;
        saa_common::ensure!(success, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }

}