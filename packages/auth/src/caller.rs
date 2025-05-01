#[cfg(feature = "wasm")]
use saa_common::{wasm::{Api, MessageInfo}, utils::prefix_from_address};
use saa_common::{AuthError, CredentialId, Verifiable};
use saa_schema::wasm_serde;


#[wasm_serde]
pub struct Caller {
    pub id: CredentialId
}


impl Caller {
    pub fn to_addr(&self) -> Result<String, AuthError> {
        String::from_utf8(self.id.clone())
        .map_err(|_| AuthError::generic("Can't derive calling address"))
    }
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
            return match self.to_addr() {
                Ok(addr) => Some(prefix_from_address(addr.as_str())),
                Err(_) => None
            }
        }
        None
    }

    fn validate(&self) -> Result<(), AuthError> {
        self.to_addr()?;
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.validate()
    }

    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self, api: &dyn Api) -> Result<(), AuthError> {
        api.addr_validate(self.to_addr()?.as_str())?;
        Ok(())
    }

}