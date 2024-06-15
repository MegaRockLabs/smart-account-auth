#[cfg(feature = "cosmwasm")]
use cosmwasm_std::ensure;
use cosmwasm_std::{Api, Env, MessageInfo};

use saa_schema::wasm_serde;

use saa_common::{
    AuthError, Binary, CredentialId, ToString, String, Verifiable 
};


#[wasm_serde]
pub struct PasskeyCredential {
    pub id          :  Binary,
    pub url         :  String,
    pub credential  :  Binary,
}


impl Verifiable for PasskeyCredential {

    fn id(&self) -> CredentialId {
        self.id.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        ensure!(!self.url.is_empty(), AuthError::MissingData("URL must be provided".to_string()));
        Ok(())
    }

    fn verify(&self) -> Result<(), AuthError> {
        Ok(())
    }

    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(&self, api: &dyn Api, _: &Env, _: &MessageInfo) -> Result<Self, AuthError> {
        Ok(self.clone())
    }
}

