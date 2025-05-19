#[cfg(feature = "wasm")]
use saa_common::{wasm::{Api, MessageInfo}, utils::prefix_from_address};
use saa_common::{AuthError, CredentialId, Verifiable};
use saa_schema::saa_type;


#[saa_type]
pub struct Caller(
    #[cfg_attr(feature = "wasm", schemars(with = "String"))]
    pub CredentialId
);



impl From<&str> for Caller {
    fn from(s: &str) -> Self {
        Caller(s.to_string())
    }
}

#[cfg(feature = "wasm")]
impl From<&MessageInfo> for Caller {
    fn from(info: &MessageInfo) -> Self {
        Caller(info.sender.to_string())
    }
}



impl Verifiable for Caller {

    fn id(&self) -> CredentialId {
        self.0.clone()
    }

    fn hrp(&self) -> Option<String> {
        #[cfg(feature = "wasm")]
        {
            return Some(prefix_from_address(&self.0))
        }
        None
    }

    fn validate(&self) -> Result<(), AuthError> {
        saa_common::ensure!(
            self.0.len() > 0,
            AuthError::MissingData("Missing calling address".to_string())
        );
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.validate()
    }

    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self, api: &dyn Api) -> Result<(), AuthError> {
        api.addr_validate(self.0.as_str())?;
        Ok(())
    }

}