use saa_schema::saa_type;
use crate::Binary;



#[saa_type(no_deny)]
#[non_exhaustive]
pub struct ClientDataOtherKeys {
    pub other_keys_can_be_added_here :  Option<String>,
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




#[saa_type(no_deny)]
pub struct PasskeyPayload {
    /// client data other keys
    pub other_keys :  Option<ClientDataOtherKeys>,
    // reserved for future use
    pub origin: Option<String>
}



#[saa_type]
pub struct PasskeyInfo {
    /// webauthn Authenticator data
    pub authenticator_data: Binary,
    /// Origin of the client where the passkey was created
    pub origin: String,
    /// Secpk256r1 Public key used for verification 
    pub pubkey: Binary,
    /// Optional user handle reserved for future use
    pub user_handle: Option<String>,
    // Flag to allow cross origin requests
    #[cfg_attr(feature = "wasm", serde(rename = "crossOrigin"))]
    pub cross_origin: bool,
}

