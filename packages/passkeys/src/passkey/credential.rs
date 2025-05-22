use saa_common::{AuthError, Binary, CredentialId, String, Verifiable, ensure};
use saa_schema::saa_type;

use super::client_data::ClientData;

// expand later after adding implementations for other platforms




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
    #[cfg_attr(feature = "cosmwasm", serde(rename = "crossOrigin"))]
    pub cross_origin: bool,
    /// Optional user handle reserved for future use
    pub user_handle: Option<String>,
}





impl PasskeyCredential {
    
    pub fn base64_message_bytes(&self) -> Result<Vec<u8>, AuthError> {
        let base64_str = super::utils::url_to_base64(&self.client_data.challenge);
        let binary = Binary::from_base64(&base64_str)
            .map_err(|_| AuthError::PasskeyChallenge)?;
        Ok(binary.to_vec())
    }

    #[cfg(any(feature = "cosmwasm", feature = "native"))]
    fn message_digest(&self) -> Result<Vec<u8>, AuthError> {
        let client_data_hash = saa_crypto::sha256(&saa_common::to_json_binary(&self.client_data)?);
        let final_digest = saa_crypto::sha256(
            &[self.authenticator_data.as_slice(), client_data_hash.as_slice()].concat()
        );
        Ok(final_digest)
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
        let res = saa_crypto::secp256r1_verify(
            &self.message_digest()?,
            &self.signature,
            self.pubkey.as_ref().unwrap()
        )?;
        ensure!(res, AuthError::generic("Passkey Signature verification failed"));
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(
        &self,  
        #[allow(unused_variables)]    
        api : &dyn saa_common::wasm::Api
    ) -> Result<(), AuthError> {
        #[cfg(feature = "no_api_r1")]
        let res = saa_crypto::secp256r1_verify(
            &self.message_digest()?,
            &self.signature,
            self.pubkey.as_ref().unwrap()
        )?;
        #[cfg(not(feature = "no_api_r1"))]
        let res = api.secp256r1_verify(
            &self.message_digest()?,
            &self.signature,
            &self.pubkey.as_ref().unwrap()
        )?;
        ensure!(res, AuthError::Signature("Passkey Signature verification failed".to_string()));
        Ok(())
    }

}

