#[cfg(feature = "session")]
mod impls;
#[cfg(feature = "session")]
pub mod actions;
#[cfg(feature = "replay")]
pub mod replay;
#[cfg(feature = "wasm")]
pub mod utils;




/// Payload message used for telling which credential to use
/// or how to modify it
#[saa_schema::wasm_serde]
pub struct AuthPayload {
    /// Human readable prefix to use to derive an address
    pub hrp             :   Option<String>,
    /// Other fields reserved for future use
    pub extension       :   Option<saa_common::Binary>,
    /// Which credential to use if multiple are available
    pub credential_id   :   Option<saa_common::CredentialId>,
}



/// A wrapper for signed data used for constructing credentials and verifying them
/// `data` is base64 encoded JSON string that contains the data to be verified.  
/// When `replay` feature tag is enabled, must be a JSON object corresponding to `MsgDataToSign` struct.
#[saa_schema::wasm_serde]
pub struct SignedDataMsg {
    /// Base64 encoded JSON string of replay envelope, serialized actions messages, both of them or none of them
    pub data        :   saa_common::Binary,
    /// Signature to verify the data
    pub signature   :   saa_common::Binary,
    /// Optional payload to use customize the verification flow if possible
    pub payload     :   Option<AuthPayload>,
}

