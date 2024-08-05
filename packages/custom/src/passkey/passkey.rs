#[cfg(feature = "cosmwasm")]
use cosmwasm_std::{Api, Env, MessageInfo};

use saa_curves::secp256r1::secp256r1_verify;
use saa_schema::wasm_serde;

use saa_common::{
    hashes::sha256, AuthError, Binary, CredentialId, String, Verifiable, ensure
};

use sha2::{Digest, Sha256};


#[derive(
    Clone,
    Debug,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
)]
#[cfg_attr(feature = "cosmwasm", 
    derive(::saa_schema::schemars::JsonSchema ),
    schemars(crate = "::saa_schema::schemars")
)]
#[cfg_attr(feature = "substrate", derive(
    ::saa_schema::scale::Encode, 
    ::saa_schema::scale::Decode
))]
#[cfg_attr(feature = "solana", derive(
    ::saa_schema::borsh::BorshSerialize, 
    ::saa_schema::borsh::BorshDeserialize
))]
#[cfg_attr(all(feature = "std", feature="substrate"), derive(
    saa_schema::scale_info::TypeInfo)
)]
#[allow(clippy::derive_partial_eq_without_eq)]
pub struct ClientData {
    // rename to type
    #[serde(rename = "type")]
    pub ty: String,
    pub challenge: String,
    pub origin: String,
    #[serde(rename = "crossOrigin")]
    pub cross_origin: bool
}


#[wasm_serde]
pub struct PasskeyCredential {
    pub id                   :       Binary,
    pub signature            :       Binary,
    pub authenticator_data   :       Binary,
    pub client_data          :       ClientData,
    /// Optional user handle reserved for future use
    pub user_handle          :       Option<String>,
    /// Public key is essential for verification but can be supplied on the contract side
    /// and omitted by client
    pub public_key           :       Option<Binary>,
}


impl Verifiable for PasskeyCredential {

    fn id(&self) -> CredentialId {
        self.id.clone().0
    }

    fn validate(&self) -> Result<(), AuthError> {
        ensure!(self.authenticator_data.len() >= 37, AuthError::generic("Invalid authenticator data"));
        ensure!(self.signature.len() > 0, AuthError::generic("Empty signature"));
        ensure!(self.client_data.challenge.len() > 0, AuthError::generic("Empty challenge"));
        ensure!(self.client_data.ty == "webauthn.get", AuthError::generic("Invalid client data type"));
        ensure!(self.public_key.is_some(), AuthError::generic("Missing public key"));
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        let client_data_hash = sha256(saa_common::to_json_binary(&self.client_data)?.as_slice());
        let mut hasher = Sha256::new();
        hasher.update(&self.authenticator_data);
        hasher.update(&client_data_hash);
        let hash = hasher.finalize();

        let res = secp256r1_verify(
            &hash,
            &self.signature,
            self.public_key.as_ref().unwrap()
        )?;
        ensure!(res, AuthError::generic("Signature verification failed"));
        Ok(())
    }

    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(&self, _: &dyn Api, _: &Env, _: &Option<MessageInfo>) -> Result<Self, AuthError> {
        let client_data_hash = sha256(saa_common::to_json_binary(&self.client_data)?.as_slice());
        let mut hasher = Sha256::new();
        hasher.update(&self.authenticator_data);
        hasher.update(&client_data_hash);
        let hash = hasher.finalize();

        let res = secp256r1_verify(
            &hash,
            &self.signature,
            self.public_key.as_ref().unwrap()
        )?;
        ensure!(res, AuthError::generic("Signature verification failed"));
        Ok(self.clone())
    }
}

