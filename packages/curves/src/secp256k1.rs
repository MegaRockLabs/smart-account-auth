use saa_schema::saa_type;
use saa_common::{
ensure, AuthError, Binary, CredentialError, CredentialId, CredentialInfo, CredentialName, 
    Verifiable, Identifiable
};

use CredentialName::Secp256k1 as Name;


#[saa_type]
pub struct Secp256k1 {
    pub pubkey:    Binary,
    pub message:   Binary,
    pub signature: Binary,
    pub hrp:       Option<String>
}


impl Identifiable for Secp256k1 {
    fn cred_id(&self) -> CredentialId {
        self.pubkey.to_base64()
    }
    fn name(&self) -> CredentialName {
        Name
    }
}


impl Verifiable for Secp256k1 {

    fn message(&self) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Borrowed(&self.message)
    }

    fn validate(&self) -> Result<(), AuthError> {
        ensure!(self.signature.len() > 0 &&
                self.message.len() > 0 && 
                self.pubkey.len() > 0,
            CredentialError::MissingData(CredentialName::Secp256k1)
        );
        Ok(())
    }

    #[cfg(any(feature = "native", feature = "cosmwasm"))]  
    fn verify(&self,
        #[cfg(feature = "cosmwasm")]
        deps: saa_common::wasm::Deps
    ) -> Result<CredentialInfo, AuthError> {
        #[cfg(not(feature = "cosmwasm"))]
        let res = saa_crypto::secp256k1_verify(
            &saa_crypto::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        #[cfg(feature = "cosmwasm")]
        let res = deps.api.secp256k1_verify(
            &saa_crypto::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature(Name, self.cred_id()));
        Ok(CredentialInfo {
            extension: None,
            address: None,
            hrp: self.hrp.clone(),
            name: Name,
        })
    }
}


#[cfg(feature = "replay")]
impl saa_crypto::ReplayProtection for Secp256k1 {}