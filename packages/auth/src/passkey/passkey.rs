use saa_schema::wasm_serde;
use saa_common::{AuthError, Binary, CredentialId, String, Verifiable, ensure};

// expand later after adding implementations for other platforms
#[cfg(any(feature = "wasm", feature = "native"))]
use {
    saa_common::hashes::sha256,
    sha2::{Digest, Sha256}
};

// Enforce serde for now until figuring how to rename fields with other serialization libraries
#[derive(
    Clone, Debug, PartialEq,
    ::saa_schema::serde::Serialize,
    ::saa_schema::serde::Deserialize
)]
// Manual derivation due to #[deny_unknown_fields] in the macro
#[cfg_attr(feature = "wasm", 
    derive(::saa_schema::schemars::JsonSchema), 
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
#[non_exhaustive]
pub struct ClientData {
    #[serde(rename = "type")]
    pub ty: String,
    pub challenge: String,
    pub origin: String,
    #[serde(rename = "crossOrigin")]
    pub cross_origin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_keys_can_be_added_here: Option<String>,
}


impl ClientData {
    pub fn new(
        ty: impl ToString, 
        challenge: impl ToString, 
        origin: impl ToString, 
        cross_origin: bool, 
        others: bool
    ) -> Self {
        Self {
            ty: ty.to_string(),
            challenge: challenge.to_string(),
            origin: origin.to_string(),
            cross_origin,
            other_keys_can_be_added_here: if others { 
                Some("do not compare clientDataJSON against a template. See https://goo.gl/yabPex".to_string()) 
            } else { None }
        }
    }
}



#[cfg_attr(not(feature = "wasm"), derive(
    ::saa_schema::serde::Serialize,
    ::saa_schema::serde::Deserialize,
))]
#[wasm_serde]
pub struct PasskeyExtension {
    /// Origin of the client where the passkey was created
    pub origin: String,
    /// Secpk256r1 Public key used for verification 
    pub pubkey: Option<Binary>,
    // Flag to allow cross origin requests
    #[serde(rename = "crossOrigin")]
    pub cross_origin: bool,
    /// Optional user handle reserved for future use
    pub user_handle: Option<String>,
}


#[wasm_serde]
pub struct PasskeyPayload {
    /// webauthn Authenticator data
    pub authenticator_data: Binary,
    /// Public key is essential for verification but can be supplied on the contract side
    pub pubkey: Option<Binary>,
    /// client data other keys
    pub other_keys: Option<bool>,
}



#[wasm_serde]
pub struct PasskeyCredential {
    /// Passkey id
    pub id                   :       String,
    /// Secp256r1 signature
    pub signature            :       Binary,
    /// webauthn Authenticator data
    pub authenticator_data   :       Binary,
    /// Client data containg challenge, origin and type
    pub client_data          :       ClientData,
    /// Optional user handle reserved for future use
    pub user_handle          :       Option<String>,
    /// Public key is essential for verification but can be supplied on the contract side
    /// and omitted by client
    pub pubkey               :       Option<Binary>,
}


#[cfg(any(feature = "wasm", feature = "native"))]
impl PasskeyCredential {
    
    pub fn base64_message_bytes(&self) -> Result<Vec<u8>, AuthError> {
        let base64_str = super::utils::url_to_base64(&self.client_data.challenge);
        let binary = Binary::from_base64(&base64_str)
            .map_err(|_| AuthError::PasskeyChallenge)?;
        Ok(binary.to_vec())
    }

    fn message_digest(&self) -> Result<Vec<u8>, AuthError> {
        let client_data_hash = sha256(saa_common::to_json_binary(&self.client_data)?.as_slice());
        let mut hasher = Sha256::new();
        hasher.update(&self.authenticator_data);
        hasher.update(&client_data_hash);
        let hash = hasher.finalize();
        Ok(hash.to_vec())
    }
}

impl Verifiable for PasskeyCredential {

    fn id(&self) -> CredentialId {
        self.id.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        ensure!(self.authenticator_data.len() >= 37, AuthError::generic("Invalid authenticator data"));
        ensure!(self.signature.len() > 0, AuthError::generic("Empty signature"));
        ensure!(self.client_data.challenge.len() > 0, AuthError::generic("Empty challenge"));
        ensure!(self.client_data.ty == "webauthn.get", AuthError::generic("Invalid client data type"));
        ensure!(self.pubkey.is_some(), AuthError::generic("Missing public key"));
        self.base64_message_bytes()?;
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        let res = saa_common::crypto::secp256r1_verify(
            &self.message_digest()?,
            &self.signature,
            self.pubkey.as_ref().unwrap()
        )?;
        ensure!(res, AuthError::generic("Passkey Signature verification failed"));
        Ok(())
    }


    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self, _ : &dyn saa_common::wasm::Api) -> Result<(), AuthError> {
        let res = saa_curves::secp256r1::implementation::secp256r1_verify(
            &self.message_digest()?,
            &self.signature,
            &self.pubkey.as_ref().unwrap()
        )?;
        ensure!(res, AuthError::Signature("Passkey Signature verification failed".to_string()));
        Ok(())
    }

}

