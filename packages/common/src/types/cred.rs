use saa_schema::{saa_type, strum_macros::{Display, EnumString}};
use crate::Binary;

pub type CredentialId = String;


#[saa_type]
#[derive(Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum CredentialName {
    Native,
    #[cfg(feature = "cosmos_arb")]
    CosmosArbitrary,
    #[cfg(feature = "eth_personal")]
    EthPersonalSign,
    #[cfg(feature = "passkeys")]
    Passkey,
    #[cfg(feature = "secp256r1")]
    Secp256r1,
    #[cfg(feature = "secp256k1")]
    Secp256k1,
    #[cfg(feature = "ed25519")]
    Ed25519,
}


#[saa_type(no_deny)]
#[non_exhaustive]
pub enum InfoExtension {
    Passkey(super::passkey::PasskeyExtension),
    Custom(Binary),
}


#[saa_type(no_deny)]
#[non_exhaustive]
pub enum PayloadExtension {
    Passkey(super::passkey::PasskeyPayload),
    Custom(Binary),
}




#[saa_type]
pub struct CredentialInfo {
    /// name of the used credential
    pub name: CredentialName,
    /// human readable prefix to encode from a public key
    pub hrp: Option<String>,
    /// extension data
    pub extension: Option<InfoExtension>,
    /// address derived from credential
    #[cfg(feature = "wasm")]
    pub address: Option<crate::wasm::Addr>,
    #[cfg(not(feature = "wasm"))]
    pub address: Option<crate::String>,
}



pub type CredentialRecord = (CredentialId, CredentialInfo);



#[cfg(feature = "wasm")]
impl From<crate::wasm::Addr> for CredentialInfo {
    fn from(addr: crate::wasm::Addr) -> Self {
        CredentialInfo {
            name: CredentialName::Native,
            hrp: addr.as_str().split("1").next().map(|s| s.to_string()),
            extension: None,
            address: Some(addr),
        }
    }
}