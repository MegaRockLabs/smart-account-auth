use crate::{Binary, String};
use std::collections::BTreeMap;
use saa_schema::saa_type;
use ethers_core::types::transaction::eip712::Eip712DomainType as CoreDomainType;

pub type Eip712Types    =  BTreeMap<String, Vec<Eip712DomainType>>;

pub type Eip712Message  =  BTreeMap<String, serde_json::Value>;


#[saa_type]
pub struct Eip712DomainType {
    pub name: String,
    #[serde(rename = "type")]
    pub r#type: String,
}





#[saa_type]
pub struct Eip712Domain {
    ///  The user readable name of signing domain, i.e. the name of the DApp or the protocol.
    pub name: Option<String>,
    /// The current major version of the signing domain. Signatures from different versions are not compatible.
    pub version: Option<String>,
    /// The EIP-155 chain id. The user-agent should refuse signing if it does not match the currently active chain.
    #[serde(rename = "chainId", skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<crate::Uint64>,
    /// The address of the contract that will verify the signature.
    #[serde(rename = "verifyingContract")]
    pub verifying_contract: Option<String>,
    /// A disambiguating salt for the protocol. This can be used as a domain separator of last resort.
    pub salt: Option<[u8; 32]>,
}





#[saa_type]
pub struct EthTypedCache {
    pub chain_id         :  Option<[u8; 32]>,
    pub contract_addr    :  Option<[u8; 32]>,
    pub domain_digest    :  Option<[u8; 32]>,
    pub preamble_digest  :  Vec<u8>,
    pub use_salt         :  bool,
}



#[saa_type]
pub struct EthTypedInfo {
    pub addr_hash   :  Option<String>,
    pub pre_hash    :  Vec<u8>,
    pub salt_used   :  bool,
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

impl Into<CoreDomainType> for Eip712DomainType {
    fn into(self) -> CoreDomainType {
        CoreDomainType {
            name: self.name,
            r#type: self.r#type,
        }
    }
}

