#[cfg(feature = "wasm")]
use saa_common::{wasm::{Api, MessageInfo}, utils::prefix_from_address};
use saa_common::{AuthError, CredentialId, Verifiable};
use saa_schema::wasm_serde;


#[wasm_serde]
pub struct Caller {
    pub id: CredentialId
}



#[cfg(feature = "wasm")]
impl From<&MessageInfo> for Caller {
    fn from(info: &MessageInfo) -> Self {
        Caller {
            id: info.sender.to_string()
        }
    }
}



impl Verifiable for Caller {

    fn id(&self) -> CredentialId {
        self.id.clone()
    }

    fn hrp(&self) -> Option<String> {
        #[cfg(feature = "wasm")]
        {
            return Some(prefix_from_address(&self.id))
        }
        None
    }

    fn validate(&self) -> Result<(), AuthError> {
        saa_common::ensure!(
            self.id.len() > 0,
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
        api.addr_validate(self.id.as_str())?;
        Ok(())
    }

}