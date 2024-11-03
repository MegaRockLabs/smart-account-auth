#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env, MessageInfo};
use saa_common::{ensure, AuthError, Binary, CredentialId, CredentialInfo, CredentialName, ToString, Verifiable};
use saa_schema::wasm_serde;


#[wasm_serde]
pub struct Caller {
    pub id: CredentialId
}


#[cfg(feature = "substrate")]
impl From<&[u8]> for Caller {
    fn from(bytes: &[u8]) -> Self {
        Caller {
            id: bytes.to_vec()
        }
    }
}


#[cfg(feature = "cosmwasm")]
impl From<&MessageInfo> for Caller {
    fn from(info: &MessageInfo) -> Self {
        Caller {
            id: info.sender.as_bytes().to_vec()
        }
    }
}



impl Verifiable for Caller {

    fn id(&self) -> CredentialId {
        self.id.clone()
    }

    fn info(&self) -> CredentialInfo {
        CredentialInfo {
            name: CredentialName::Caller,
            hrp: None,
            extension: None
        }
    }

    // mock implementation
    fn message(&self) -> Binary {
        Binary(self.id.clone())
    }


    fn validate(&self) -> Result<(), AuthError> {
        let id = self.id();
        if !(id.len() > 3) {
            return Err(AuthError::MissingData("Caller must have an id".to_string()));
        }
        ensure!(String::from_utf8(id).is_ok(), AuthError::generic("Can't derove calling address"));
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.validate()
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(& self, _: &dyn Api, _: &Env) -> Result<(), AuthError> {
        self.validate()
    }

}