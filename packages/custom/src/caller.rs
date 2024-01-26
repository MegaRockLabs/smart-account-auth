#[cfg(feature = "cosmwasm")]
use saa_common::{Api, Env, MessageInfo, from_json};


use saa_common::{AuthError, CredentialId, Verifiable};
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



#[cfg(all(feature = "cosmwasm"))]
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

    fn validate(&self) -> Result<(), AuthError> {
        if !(self.id.len() > 0) {
            return Err(AuthError::InvalidLength("Caller must have an id".to_string()));
        }
        Ok(())
    }

    fn verify(&self) -> Result<(), AuthError> {
        Ok(())
    }

    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(& self, api: &dyn Api, _: &Env, _: &MessageInfo) -> Result<Self, AuthError> {
        let addr : String = from_json(&self.id)?;
        api.addr_validate(&addr)?;
        Ok(self.clone())
    }
}