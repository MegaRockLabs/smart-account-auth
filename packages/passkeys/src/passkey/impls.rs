use crate::{PasskeyCredential, PasskeyInfo};
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