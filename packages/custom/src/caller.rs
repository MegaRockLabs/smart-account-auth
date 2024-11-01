#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env, MessageInfo, Addr};
#[cfg(all(feature = "cosmwasm", feature = "storage"))]
use saa_common::{storage::*, cosmwasm::Storage, ensure};

use saa_common::{AuthError, Binary, ToString, Verifiable, CredentialId, CredentialInfo, CredentialName};
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

impl From<&str> for Caller {
    fn from(str: &str) -> Self {
        Caller {
            id: str.as_bytes().to_vec()
        }
    }
}


#[cfg(feature = "cosmwasm")]
impl From<&MessageInfo> for Caller {
    fn from(info: &MessageInfo) -> Self {
        info.sender.as_str().into()
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
        if !(self.id.len() > 3) {
            return Err(AuthError::MissingData("Caller must have an id".to_string()));
        }
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.validate()?;
        String::from_utf8(self.id.clone())?;
        Ok(())
    }

    #[cfg(feature = "cosmwasm")]
    fn cosmos_address(&self, _: &dyn Api) -> Result<Addr, AuthError> {
        let addr : String = String::from_utf8(self.id.clone())?;
        Ok(cosmwasm_std::Addr::unchecked(addr))
    }

    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(& self, api: &dyn Api, _: &Env) -> Result<(), AuthError> {
        self.cosmos_address(api)?;
        Ok(())
    }


    #[cfg(all(feature = "cosmwasm", feature = "storage"))]
    fn assert_query_cosmwasm<D>(
        &self, 
        _       : &dyn Api,
        storage : &dyn Storage, 
        _       : &Env,
        info    : &Option<MessageInfo>
    ) -> Result<String, AuthError> 
        where D: schemars::JsonSchema + serde::de::DeserializeOwned
    {
        ensure!(info.is_some(), AuthError::generic("MessageInfo must be passed to verify Caller"));

        let stored  = CALLER.load(storage).unwrap_or(None);
        ensure!(stored.is_some(), AuthError::generic("Caller address is not stored"));

        let stored = stored.unwrap();
        let sender = info.as_ref().unwrap().sender.clone();
        ensure!(stored == sender, AuthError::generic("Caller address does not match"));

        let info= CREDENTIAL_INFOS.load(storage, self.id());
        ensure!(
            info.is_ok() && info.unwrap().name == CredentialName::Caller, 
            AuthError::generic("Caller info not found")
        );
 
        Ok(String::default())
    }

    #[cfg(all(feature = "cosmwasm", feature = "storage"))]
    fn save_cosmwasm<D>(
        &self, 
        _       : &dyn Api, 
        storage : &mut dyn Storage,
        _       : &Env, 
        info    : &Option<MessageInfo>
    ) -> Result<Self, AuthError> 
        where Self : Clone, D: schemars::JsonSchema + serde::de::DeserializeOwned 
    {
        ensure!(info.is_some(), AuthError::generic("MessageInfo must be passed for the Caller"));
        CREDENTIAL_INFOS.save(storage, self.id(), &self.info())?;
        CALLER.save(storage, &Some(info.as_ref().unwrap().sender.to_string()))?;
        Ok(self.clone())
    }


}