use saa_schema::wasm_serde;
use crate::Binary;


pub type CredentialId = Vec<u8>;



#[wasm_serde]
pub enum CredentialName {
    Caller,
    CosmosArbitrary,
    EthPersonalSign,
    Passkey,
    Secp256k1,
    Secp256r1,
    Ed25519,
}


#[wasm_serde]
pub struct CredentialInfo {
    /// name of the used credential
    pub name: CredentialName,
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
