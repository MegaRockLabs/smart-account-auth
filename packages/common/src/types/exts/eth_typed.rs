use crate::{Binary, String};
use saa_schema::saa_type;

#[saa_type]
pub struct EthTypedCache {
    pub chain_id         :  Option<[u8; 32]>,
    pub contract_addr    :  Option<[u8; 32]>,
    pub domain_digest    :  Option<[u8; 32]>,
    pub preamble_digest  :  Vec<u8>,
    pub use_salt         :  bool,
}

#[saa_type]
pub struct EthTypedSaveOptions {
    pub chain_id         :  Option<bool>,
    pub contract_addr    :  Option<bool>,
    pub domain_digest    :  Option<bool>,
    pub types            :  Option<bool>,
}


#[saa_type]
pub struct EthTypedInfo {
    pub primary_type    :  Option<String>,
    pub types           :  Option<Binary>,
    pub cache           :  EthTypedCache,
}



#[saa_type(no_deny)]
#[non_exhaustive]
pub struct EthTypedPayload {
    pub types           :  Option<Binary>,
    pub primary_type    :  Option<String>,
    
    pub domain          :  Option<Binary>,
    pub contract_addr   :  Option<String>,
    pub salt            :  Option<Binary>
}


impl Default for EthTypedSaveOptions {
    fn default() -> Self {
        Self {
            chain_id: Some(true),
            contract_addr: Some(true),
            domain_digest: Some(true),
            types: Some(true)
        }
    }
}

impl Default for EthTypedCache {
    fn default() -> Self {
        Self {
            chain_id: None,
            contract_addr: None,
            domain_digest: None,
            preamble_digest: vec![],
            use_salt: false,
        }
    }
}