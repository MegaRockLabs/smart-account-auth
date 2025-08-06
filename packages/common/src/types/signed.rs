use saa_schema::saa_type;
use crate::PayloadExtension;


/// Payload message used for telling which credential to use
/// or how to modify it
#[saa_type]
pub struct AuthPayload {
    /// Which credential to use if multiple are available
    pub credential_id   :   Option<crate::CredentialId>,
    /// Human readable prefix to use to derive an address
    pub hrp             :   Option<String>,
    /// Additional arguments to pass depending on a credential in question
    pub extension       :   Option<PayloadExtension>,
}



/// A wrapper for signed data used for constructing credentials and verifying them
/// `data` is base64 encoded JSON string that contains the data to be verified.  
/// When `replay` feature tag is enabled, must be a JSON object corresponding to `MsgDataToSign` struct.
#[saa_type]
pub struct SignedDataMsg {
    /// Base64 encoded JSON string of replay envelope, serialized actions messages, both of them or none of them
    pub data        :   crate::Binary,
    /// Signature to verify the data
    pub signature   :   crate::Binary,
    /// Optional payload to use customize the verification flow if possible
    pub payload     :   Option<AuthPayload>,
}



#[saa_type(no_deny)]
pub struct MsgDataToVerify {
    pub chain_id: String,
    pub contract_address: String,
    pub nonce: crate::Uint64,
}



#[derive(Debug, serde::Serialize)]
pub struct MsgDataToSign {
    pub chain_id: String,
    pub contract_address: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<String>,
    pub nonce: crate::Uint64,
}


impl MsgDataToSign {
    pub fn new(cid: String, addr: String, msgs: Vec<String>, nonce: u64) -> Self {
        Self {
            chain_id: cid,
            messages: msgs,
            contract_address: addr,
            nonce: nonce.into(),
        }
    }
}

