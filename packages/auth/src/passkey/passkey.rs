use saa_schema::saa_type;
use saa_common::{AuthError, Binary, CredentialId, String, Verifiable, ensure};

// expand later after adding implementations for other platforms
#[cfg(any(feature = "wasm", feature = "native"))]
use {
    saa_common::hashes::sha256,
    sha2::{Digest, Sha256}
};




#[saa_type]
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
    /// Public key is essential for verification but can be supplied on the backend / contract side
    /// and omitted by client. Must be set when going through the verification process.
    pub pubkey               :       Option<Binary>,
}





#[saa_type]
pub struct PasskeyInfo {
    /// webauthn Authenticator data
    pub authenticator_data: Binary,
    /// Origin of the client where the passkey was created
    pub origin: String,
    /// Secpk256r1 Public key used for verification 
    pub pubkey: Binary,
    // Flag to allow cross origin requests
    #[cfg_attr(feature = "wasm", serde(rename = "crossOrigin"))]
    pub cross_origin: bool,
    /// Optional user handle reserved for future use
    pub user_handle: Option<String>,
}





#[cfg(feature = "wasm")]
#[saa_type(no_deny)]
#[non_exhaustive]
pub struct ClientData {
    #[serde(rename = "type")]
    pub ty: String,
    pub challenge: String,
    pub origin: String,
    #[serde(rename = "crossOrigin")]
    pub cross_origin: bool,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub other_keys : Option<ClientDataOtherKeys>,
}


#[cfg(not(feature = "wasm"))]
#[saa_type(no_deny)]
#[non_exhaustive]
pub struct ClientData {
    pub ty: String,
    pub challenge: String,
    pub origin: String,
    pub cross_origin: bool,
    pub other_keys_can_be_added_here: Option<String>,
}



#[saa_type]
pub struct PasskeyPayload {
    /// client data other keys
    pub other_keys :  Option<ClientDataOtherKeys>,
    // reserved for future use
    pub origin: Option<String>
}




#[saa_type(no_deny)]
#[non_exhaustive]
pub struct ClientDataOtherKeys {
    pub other_keys_can_be_added_here :  Option<String>,
}


impl ClientData {
    pub fn new(
        ty: impl ToString, 
        challenge: impl ToString, 
        origin: impl ToString, 
        cross_origin: bool, 
        other_keys: Option<ClientDataOtherKeys>
    ) -> Self {
        Self {
            ty: ty.to_string(),
            challenge: challenge.to_string(),
            origin: origin.to_string(),
            cross_origin,
            other_keys,
        }
    }
}


impl ClientDataOtherKeys {
    pub fn new(
        other_keys_can_be_added_here: Option<String>
    ) -> Self {
        Self {
            other_keys_can_be_added_here
        }
    }
}




impl PasskeyCredential {
    
    pub fn base64_message_bytes(&self) -> Result<Vec<u8>, AuthError> {
        let base64_str = super::utils::url_to_base64(&self.client_data.challenge);
        let binary = Binary::from_base64(&base64_str)
            .map_err(|_| AuthError::PasskeyChallenge)?;
        Ok(binary.to_vec())
    }

    #[cfg(any(feature = "wasm", feature = "native"))]
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
    fn verify_cosmwasm(
        &self,  
        #[allow(unused_variables)]    
        api : &dyn saa_common::wasm::Api
    ) -> Result<(), AuthError> {

        #[cfg(feature = "cosmwasm")]
        let res = api.secp256r1_verify(
            &self.message_digest()?,
            &self.signature,
            &self.pubkey.as_ref().unwrap()
        )?;

        #[cfg(not(feature = "cosmwasm"))]
        let res = saa_curves::secp256r1::implementation::secp256r1_verify(
            &self.message_digest()?,
            &self.signature,
            &self.pubkey.as_ref().unwrap()
        )?;
        ensure!(res, AuthError::Signature("Passkey Signature verification failed".to_string()));
        Ok(())
    }

}

