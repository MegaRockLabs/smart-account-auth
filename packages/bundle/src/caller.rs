use saa_common::{AuthError, CredentialId, CredentialInfo, CredentialName, Verifiable};


#[saa_schema::saa_type]
pub struct Caller(pub CredentialId);


impl From<&str> for Caller {
    fn from(addr: &str) -> Self {
        Caller(addr.to_string())
    }
}


impl Verifiable for Caller {

    fn id(&self) -> CredentialId {
        self.0.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        saa_common::ensure!(
            self.0.len() > 3,
            AuthError::MissingData("Missing calling address".to_string())
        );
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
            address: Some(address),
            name: CredentialName::Native,
            extension: None,
        })
    }
}


