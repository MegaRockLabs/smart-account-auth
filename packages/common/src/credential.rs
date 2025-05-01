use saa_schema::wasm_serde;
use crate::Binary;


pub type CredentialId = Vec<u8>;




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
    pub credentials: Vec<(Binary, CredentialInfo)>,
    pub verifying_id: Binary,
    pub native_caller: bool,
}
