use saa_common::{AuthError, CredentialId, Verifiable};

#[saa_schema::saa_type]
pub struct Caller(pub CredentialId);



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

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.validate()
    }
    
    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self, api: &dyn saa_common::wasm::Api) -> Result<(), AuthError> {
        api.addr_validate(self.0.as_str())?;
        Ok(())
    }

    #[cfg(all(feature = "wasm", feature = "cosmos"))]
    fn hrp(&self) -> Option<String> {
        Some(saa_crypto::prefix_from_address(&self.0))
    }
}



#[cfg(feature = "wasm")]
impl From<&saa_common::wasm::MessageInfo> for Caller {
    fn from(info: &saa_common::wasm::MessageInfo) -> Self {
        Caller(info.sender.to_string())
    }
}


impl From<&str> for Caller {
    fn from(s: &str) -> Self {
        Caller(s.to_string())
    }
}

