
use saa_common::{
    ensure, AuthError, Binary, CredentialError, CredentialId, CredentialInfo, CredentialName, 
    Verifiable, Identifiable
};
use CredentialName::Ed25519 as Name;
use saa_schema::saa_type;


#[saa_type]
pub struct Ed25519 {
    pub pubkey:    Binary,
    pub message:   Binary,
    pub signature: Binary,
}


impl Identifiable for Ed25519 {

    fn id(&self) -> CredentialId {
        self.pubkey.to_base64()
    }

    fn name(&self) -> CredentialName {
        Name
    }

}


impl Verifiable for Ed25519 {


    fn message(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::Borrowed(self.message.as_slice())
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

    #[cfg(any(feature = "native", feature = "cosmwasm"))]  
    fn verify(&self,
        #[cfg(feature = "cosmwasm")]
        deps: saa_common::wasm::Deps
    ) -> Result<CredentialInfo, AuthError> {
        #[cfg(not(feature = "cosmwasm"))]
        let res = saa_crypto::ed25519_verify(
            &self.message, 
            &self.signature, 
            &self.pubkey
        )?;
        #[cfg(feature = "cosmwasm")]
        let res = deps.api.ed25519_verify(
            &self.message,
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


#[cfg(feature = "replay")]
impl saa_crypto::ReplayProtection for Ed25519 {}