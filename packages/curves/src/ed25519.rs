use std::borrow::Cow;

use saa_schema::saa_type;
use saa_common::{
    ensure, AuthError, Binary, CredentialError, CredentialId, CredentialInfo, CredentialName, ToString, Verifiable
};

use CredentialName::Ed25519 as Name;


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

    fn message(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.message.as_slice())
    }

    fn validate(&self) -> Result<(), AuthError> {
        ensure!(
            self.signature.len() > 0 &&
                self.message.len() > 0 && 
                self.pubkey.len() > 0,
            CredentialError::MissingData(Name)
        );
        Ok(())
    }

    fn verify(&self,
        #[cfg(feature = "cosmwasm")]
        deps: saa_common::wasm::Deps
    ) -> Result<CredentialInfo, AuthError> {
        #[cfg(all(feature = "native", not(feature = "cosmwasm")))]
        let res = saa_crypto::ed25519_verify(
            &saa_crypto::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        #[cfg(feature = "cosmwasm")]
        let res = deps.api.ed25519_verify(
            &saa_crypto::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature(Name, self.id()));
        Ok(CredentialInfo {
            extension: None,
            address: None,
            hrp: None,
            name: Name,
        })
    }

}