use saa_common::{AccountId, AuthError, CredentialId, Verifiable};
use saa_schema::wasm_serde;


#[wasm_serde]
pub struct Caller {
    pub id: CredentialId

}

#[cfg(feature = "substrate")]
impl From<&saa_common::AccountId> for Caller {
    fn from(id: &AccountId) -> Self {
        let r : &[u8; 32] = id.as_ref();
        Caller {
            id: r.to_vec()
        }
    }
}

#[cfg(feature = "substrate")]
impl From<saa_common::AccountId> for Caller {
    fn from(id: AccountId) -> Self {
        Self::from(&id)
    }
}

#[cfg(feature = "cosmwasm")]
impl From<&saa_common::MessageInfo> for Caller {
    fn from(info: &saa_common::MessageInfo) -> Self {
        Caller {
            id: info.sender.to_string().as_bytes().to_vec()
        }
    }
}

#[cfg(feature = "cosmwasm")]
impl From<saa_common::MessageInfo> for Caller {
    fn from(info: saa_common::MessageInfo) -> Self {
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
    fn verify_api_cosmwasm(&self, api: &dyn cosmwasm_std::Api, _: &cosmwasm_std::Env) -> Result<(), AuthError> {
        let addr : String = cosmwasm_std::from_json(&self.id)?;
        api.addr_validate(&addr)?;
        Ok(())
    }
}