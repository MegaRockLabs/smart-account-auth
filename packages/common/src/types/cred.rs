use core::fmt::Display;

use saa_schema::{saa_type, strum_macros::{Display, EnumString}};
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
    #[cfg(feature = "eth_typed_data")]
    EthTypedData, 
    #[cfg(feature = "passkeys")]
    Passkey,
    #[cfg(feature = "secp256r1")]
    Secp256r1,
    #[cfg(feature = "secp256k1")]
    Secp256k1,
    #[cfg(feature = "ed25519")]
    Ed25519,
}


#[saa_type]
pub enum CredentialAddress {
    Evm(String),
    #[cfg(not(feature = "wasm"))]
    Bech32(String),
    #[cfg(feature = "wasm")]
    Bech32(crate::wasm::Addr),
}


#[saa_type]
pub struct CredentialInfo {
    /// name of the used credential
    pub name: CredentialName,
    /// human readable prefix to encode from a public key
    pub hrp: Option<String>,
    /// extension data
    pub extension: Option<crate::InfoExtension>,
    /// address derived from credential
    pub address: Option<CredentialAddress>,
}



pub type CredentialRecord = (CredentialId, CredentialInfo);



impl Display for CredentialAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CredentialAddress::Evm(addr) => write!(f, "{}", addr),
            #[cfg(not(feature = "wasm"))]
            CredentialAddress::Bech32(addr) => write!(f, "{}", addr),
            #[cfg(feature = "wasm")]
            CredentialAddress::Bech32(addr) => write!(f, "{}", addr.as_str()),
        }
    }
    
}


#[cfg(feature = "wasm")]
impl From<crate::wasm::Addr> for CredentialInfo {
    fn from(addr: crate::wasm::Addr) -> Self {
        CredentialInfo {
            name: CredentialName::Native,
            extension: None,
            hrp: addr.as_str().split("1").next().map(|s| s.to_string()),
            address: Some(CredentialAddress::Bech32(addr)),
        }
    }
}