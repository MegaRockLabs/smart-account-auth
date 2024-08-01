#[cfg(feature = "cosmwasm")]
use cosmwasm_std::ensure;
use cosmwasm_std::{Api, Env, MessageInfo};

use saa_curves::secp256r1::secp256r1_verify;
use saa_schema::wasm_serde;

use saa_common::{
    hashes::sha256, AuthError, Binary, CredentialId, String, Verifiable 
};


#[wasm_serde]
pub struct ClientData {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(rename = "crossOrigin")]
    pub cross_origin: Option<bool>,
    pub challenge: String,
    pub origin: String,
}


#[wasm_serde]
pub struct PasskeyCredential {
    pub id                   :       Binary,
    pub signature            :       Binary,
    pub authenticator_data   :       Binary,
    pub client_data          :       ClientData,
    pub user_handle          :       Option<String>
}


impl Verifiable for PasskeyCredential {

    fn id(&self) -> CredentialId {
        self.id.clone().0
    }

    fn validate(&self) -> Result<(), AuthError> {
        ensure!(self.authenticator_data.len() >= 37, AuthError::generic("Invalid authenticator data"));
        ensure!(self.signature.len() > 0, AuthError::generic("Empty signature"));
        ensure!(self.client_data.challenge.len() > 0, AuthError::generic("Empty challenge"));
        ensure!(self.client_data.ty != "webauthn.get", AuthError::generic("Invalid client data type"));
        Ok(())
    }

    fn verify(&self) -> Result<(), AuthError> {
        let hash = sha256(&self.authenticator_data);
        let res = secp256r1_verify(
            &hash,
            &self.signature,
            &self.id
        )?;
        ensure!(res, AuthError::generic("Signature verification failed"));
        Ok(())
    }

    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(&self, _: &dyn Api, _: &Env, _: &Option<MessageInfo>) -> Result<Self, AuthError> {
        self.verify()?;
        Ok(self.clone())
    }
}

