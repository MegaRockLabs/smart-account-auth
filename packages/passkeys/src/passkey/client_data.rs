
use saa_common::String;
use saa_schema::saa_type;



/// The client data object defined by the WebAuthn standard.
#[saa_type(no_deny)]
#[non_exhaustive]
pub struct ClientData {
    /// Type of the client data. The contract expects "webauthn.get"
    #[serde(rename = "type")]
    pub ty: String,
    
    /// Base64url encoded challenge string
    pub challenge: String,
    
    /// Origin of the client where the passkey was created
    pub origin: String,
    
    /// Whether the passkey was registed with a cross-origin device 
    #[serde(rename = "crossOrigin")]
    pub cross_origin: bool,

    /// Injecting other keys into the client data
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub other_keys : Option<ClientDataOtherKeys>,
}




#[saa_type(no_deny)]
#[non_exhaustive]
pub struct ClientDataOtherKeys {
    pub other_keys_can_be_added_here :  Option<String>,
}



#[saa_type(no_deny)]
pub struct PasskeyPayload {
    /// client data other keys
    pub other_keys :  Option<ClientDataOtherKeys>,
    // reserved for future use
    pub origin: Option<String>
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


impl ClientDataOtherKeys {
    pub fn new(
        other_keys_can_be_added_here: Option<String>
    ) -> Self {
        Self {
            other_keys_can_be_added_here
        }
    }
}
