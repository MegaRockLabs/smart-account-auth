#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env, MessageInfo};
use saa_common::{AuthError, Binary, CredentialId, CredentialInfo, CredentialName, ToString, Verifiable};
use saa_schema::wasm_serde;


#[wasm_serde]
pub struct Caller {
    pub id: CredentialId
}


impl From<&[u8]> for Caller {
    fn from(bytes: &[u8]) -> Self {
        Caller {
            id: bytes.to_vec()
        }
    }
}


impl From<[u8; 32]> for Caller {
    fn from(bytes: [u8; 32]) -> Self {
        Caller {
            id: bytes.to_vec()
        }
    }
}



#[cfg(feature = "cosmwasm")]
impl From<&MessageInfo> for Caller {
    fn from(info: &MessageInfo) -> Self {
        Caller {
            id: info.sender.to_string().as_bytes().to_vec()
        }
    }
}

#[cfg(feature = "cosmwasm")]
impl From<MessageInfo> for Caller {
    fn from(info: MessageInfo) -> Self {
        Self::from(&info)
    }
}



impl Verifiable for Caller {

    fn id(&self) -> CredentialId {
        self.id.clone()
    }

    fn human_id(&self) -> String {
        String::from_utf8(self.id.clone()).unwrap()
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
        if !(self.id.len() > 0) {
            return Err(AuthError::MissingData("Caller must have an id".to_string()));
        }
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.validate()
    }

    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(& self, api: &dyn Api, _: &Env, _: &Option<MessageInfo>) -> Result<Self, AuthError> {
        self.validate()?;
        let addr : String = String::from_utf8(self.id.clone())?;
        api.addr_validate(&addr)?;
        Ok(self.clone())
    }

    #[cfg(feature = "cosmwasm")]
    fn cosmos_address(&self, _: &dyn Api) -> Result<cosmwasm_std::Addr, AuthError> {
        let addr : String = String::from_utf8(self.id.clone())?;
        Ok(cosmwasm_std::Addr::unchecked(addr))
    }
}