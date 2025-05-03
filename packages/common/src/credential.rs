use saa_schema::wasm_serde;
use crate::{Binary, String};


pub type CredentialId = String;


#[wasm_serde]
pub struct CredentialInfo {
    /// name of the used credential
    pub name: String,
    /// human readable prefix to encode from a public key
    pub hrp: Option<String>,
    /// extension data
    pub extension: Option<Binary>,
}




#[wasm_serde]
pub struct AccountCredentials {
    pub credentials: Vec<(CredentialId, CredentialInfo)>,
    pub verifying_id: CredentialId,
    pub native_caller: Option<CredentialId>,
}
