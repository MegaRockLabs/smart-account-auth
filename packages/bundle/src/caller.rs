use saa_common::{
    AuthError, CredentialAddress, CredentialError, CredentialId, CredentialInfo, CredentialName, Identifiable, Verifiable
};


use CredentialName::Native;


#[saa_schema::saa_type]
pub struct Caller(pub CredentialId);


impl From<&str> for Caller {
    fn from(addr: &str) -> Self {
        Caller(addr.to_string())
    }
}


impl Identifiable for Caller {

    fn id(&self) -> CredentialId {
        self.0.to_lowercase()
    }

    fn name(&self) -> CredentialName {
        Native
    }
}


impl Verifiable for Caller {

     fn message(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::Owned(vec![])
    }

    fn validate(&self) -> Result<(), AuthError> {
        saa_common::ensure!(self.0.len() > 3, CredentialError::MissingData(Native));
        Ok(())
    }
    
    fn verify(&self,
        #[cfg(feature = "wasm")]
        deps: saa_common::wasm::Deps
    ) -> Result<CredentialInfo, AuthError> {
        #[cfg(feature = "wasm")]
        let address = deps.api.addr_validate(self.0.as_str())?;
        #[cfg(feature = "wasm")]
        let hrp = address.as_str().split("1").next().map(|s| s.to_string());
        #[cfg(not(feature = "wasm"))]
        let address = self.0.clone();
        #[cfg(not(feature = "wasm"))]
        let hrp = None;
        
        Ok(CredentialInfo {
            hrp,
            extension: None,
            name: Native,
            address: Some(CredentialAddress::Bech32(address)),
        })
    }
}


#[cfg(feature = "replay")]
impl saa_crypto::ReplayProtection for Caller {

    #[cfg(not(feature = "optimise"))]
    fn protect_reply<M: serde::Serialize + core::fmt::Display + Clone>(
            &self,
            #[cfg(feature = "wasm")]
            _: &saa_common::wasm::Env, 
            _: saa_crypto::ReplayParams<M>,
        ) -> Result<(), saa_common::ReplayError> {
        return Ok(());
    }

    #[cfg(feature = "optimise")]
    fn protect_reply(
        &self,
        #[cfg(feature = "wasm")]
        _: &saa_common::wasm::Env, 
        _: saa_crypto::ReplayParams,
    ) -> Result<(), saa_common::ReplayError> {
        return Ok(());
    }
}
