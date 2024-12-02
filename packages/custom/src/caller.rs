#[cfg(feature = "wasm")]
use saa_common::{cosmwasm::{Api, MessageInfo}, utils::prefix_from_address};
use saa_common::{ensure, AuthError, CredentialId, ToString, Verifiable};
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


#[cfg(feature = "wasm")]
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

    fn hrp(&self) -> Option<String> {
        #[cfg(feature = "wasm")]
        {
            let res = String::from_utf8(self.id.clone());
            if res.is_err() {
                return None;
            }
            return Some(prefix_from_address(res.unwrap().as_str()));
        }
        None
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


    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(& self, _: &dyn Api) -> Result<(), AuthError> {
        self.validate()
    }

}