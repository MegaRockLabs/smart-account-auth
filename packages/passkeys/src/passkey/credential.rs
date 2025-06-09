use saa_schema::saa_type;
use saa_crypto::{sha256, ReplayProtection};
use saa_common::{ensure, to_json_binary, AuthError, Binary, CredentialError, CredentialInfo, CredentialName, Identifiable, String, Verifiable
};

use super::client_data::ClientData;
use CredentialName::Passkey as PasskeyName;


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



impl Identifiable for PasskeyCredential {

    fn id(&self) -> saa_common::CredentialId {
        self.id.clone()
    }

    fn name(&self) -> saa_common::CredentialName {
        PasskeyName
    }
}



/* impl PasskeyCredential {
    

    #[allow(unused)]
    #[cfg(any(feature = "cosmwasm", feature = "native"))]
    fn message_digest(&self) -> Result<[u8; 32], AuthError> {
        let client_data_hash = saa_crypto::sha256(&saa_common::to_json_binary(&self.client_data)?);
        let final_digest = saa_crypto::sha256(
            &[self.authenticator_data.as_slice(), client_data_hash.as_slice()].concat()
        );
        Ok(final_digest)
    }
}
 */



impl Verifiable for PasskeyCredential {

    // transfroming from base64 url to regular base64 so that we can deserialize using `from_json` etc.
    fn message(&self) -> std::borrow::Cow<[u8]> {
        match Binary::from_base64(&super::utils::url_to_base64(&self.client_data.challenge)) {
            Ok(bytes) => std::borrow::Cow::Owned(bytes.to_vec()),
            Err(_) => std::borrow::Cow::Borrowed(&[])
        }
    }

    fn validate(&self) -> Result<(), AuthError> {
        ensure!(
            self.signature.len() > 0 &&
            self.authenticator_data.len() > 0 &&
            self.client_data.challenge.len() > 0 &&
            self.message().len() > 0, CredentialError::MissingData(PasskeyName)
        );
        ensure!(self.authenticator_data.len() >= 37, CredentialError::InvalidProperty(
            PasskeyName, "authenticator_data".to_string(), "must be at least 37 bytes long".to_string()
        ));
        ensure!(self.client_data.ty == "webauthn.get", CredentialError::InvalidProperty(
            PasskeyName, "client_data.type".to_string(), "must be 'webauthn.get'".to_string()
        ));
        Ok(())
    }


    #[allow(unused_variables)]
    #[cfg(any(feature = "cosmwasm", feature = "native"))]
    fn verify(&self,
        #[cfg(feature = "cosmwasm")]
        deps: saa_common::wasm::Deps
    ) -> Result<CredentialInfo, AuthError> {
        let res = true;
        #[cfg(all(any(feature = "native", feature = "no_api_r1"), not(feature = "cosmwasm")))]
        let res = saa_crypto::secp256r1_verify(
            &self.message_digest(),
            &self.signature,
            self.pubkey.as_ref().unwrap()
        )?;
        #[cfg(all(feature = "cosmwasm", not(feature = "no_api_r1")))]
        let res = deps.api.secp256r1_verify(
            &self.message_digest(),
            &self.signature,
            &self.pubkey.as_ref().unwrap()
        )?;
        ensure!(res, AuthError::Signature(PasskeyName, self.id()));
        Ok(CredentialInfo { extension: None, address: None, hrp: None, name: PasskeyName })
    }

}



impl ReplayProtection for PasskeyCredential {

    fn message_digest(&self) -> Vec<u8> {
        let client_data_hash = sha256(&to_json_binary(&self.client_data).unwrap());
        let final_digest = sha256(
            &[self.authenticator_data.as_slice(), client_data_hash.as_slice()].concat()
        );
        final_digest.to_vec()
    }
}