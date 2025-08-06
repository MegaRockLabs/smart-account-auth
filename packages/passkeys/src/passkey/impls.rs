use crate::{ClientData, ClientDataOtherKeys, PasskeyCredential, PasskeyInfo};
use saa_common::InfoExtension;


impl Into<PasskeyInfo> for PasskeyCredential {
    fn into(self) -> PasskeyInfo {
        PasskeyInfo {
            origin: self.client_data.origin,
            cross_origin: self.client_data.cross_origin,
            user_handle: self.user_handle,
            authenticator_data: self.authenticator_data,
            pubkey: self.pubkey.unwrap_or_default(),
        }
    }
}

impl Into<InfoExtension> for PasskeyCredential {
    fn into(self) -> InfoExtension {
        InfoExtension::Passkey(self.into())
    }
    
}




impl ClientData {
    pub fn new(
        challenge: impl ToString, 
        origin: impl ToString, 
        cross_origin: bool, 
        other_keys: Option<ClientDataOtherKeys>
    ) -> Self {
        Self {
            ty: "webauthn.get".into(),
            challenge: challenge.to_string(),
            origin: origin.to_string(),
            cross_origin,
            other_keys,
        }
    }
}



impl PasskeyCredential {
    
    #[allow(unused, dead_code)]
    pub(crate) fn data_hash(&self) -> Result<[u8; 32], saa_common::AuthError> {
        
        Ok(saa_crypto::sha256(&[
            self.authenticator_data.as_slice(), 
            &saa_crypto::sha256(
                &saa_common::to_json_binary(&self.client_data)?
            )
        ].concat()))
    }
}
 



#[cfg(feature = "replay")]
impl saa_crypto::ReplayProtection for PasskeyCredential {}