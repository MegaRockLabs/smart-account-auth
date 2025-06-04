use saa_common::{types::passkey::PasskeyExtension, InfoExtension};
use crate::passkey::PasskeyCredential;


impl Into<PasskeyExtension> for PasskeyCredential {
    fn into(self) -> PasskeyExtension {
        PasskeyExtension {
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