use std::collections::BTreeMap;
use saa_common::Uint64;
use saa_schema::saa_type;
use serde_json::Value;

use crate::eth::utils::{encode_address, encode_u64, hash_eth_typed_data, preamble_hash_eth_typed};
use ethers_core::types::transaction::eip712::Eip712DomainType as CoreDomainType;


#[saa_type]
pub struct Eip712DomainType {
    pub name: String,
    #[serde(rename = "type")]
    pub r#type: String,
}

impl Into<CoreDomainType> for Eip712DomainType {
    fn into(self) -> CoreDomainType {
        CoreDomainType {
            name: self.name,
            r#type: self.r#type,
        }
    }
}

pub type Eip712Types = BTreeMap<String, Vec<Eip712DomainType>>;

pub type Eip712Message  =  BTreeMap<String, Value>;




#[saa_type]
pub struct Eip712Domain {
    ///  The user readable name of signing domain, i.e. the name of the DApp or the protocol.
    pub name: String,
    /// The current major version of the signing domain. Signatures from different versions are not compatible.
    pub version: String,
    /// The EIP-155 chain id. The user-agent should refuse signing if it does not match the currently active chain.
    #[serde(rename = "chainId")]
    pub chain_id: Uint64,
    /// The address of the contract that will verify the signature.
    #[serde(rename = "verifyingContract")]
    pub verifying_contract: String,
    /// A disambiguating salt for the protocol. This can be used as a domain separator of last resort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<[u8; 32]>,
}



#[saa_type]
pub struct Eip712DomainValues {
    pub chain_id         :  [u8; 32],
    pub contract_addr    :  [u8; 32],
    pub domain_digest    :  [u8; 32],
    pub preamble_digest  :  Vec<u8>,
    pub use_salt         :  bool,
}


impl Eip712DomainValues {
    pub fn to_cached(&self, options: super::EthTypedSaveOptions) -> super::EthTypedCache {
        super::EthTypedCache {
            
            use_salt: self.use_salt,

            preamble_digest: self.preamble_digest.clone(),

            chain_id: if options.chain_id.unwrap_or_default() { 
                Some(self.chain_id) } else { None },

            contract_addr: if options.contract_addr.unwrap_or_default() { 
                Some(self.contract_addr) 
            } else { None },

            domain_digest: if options.domain_digest.unwrap_or_default() { 
                Some(self.domain_digest) 
            } else { None },
        }
    }
    
}


impl Eip712Domain {

    pub(crate) fn compute_values(
        &self,
        cache: Option<super::EthTypedCache>
    ) -> Eip712DomainValues {
        let cache = cache.unwrap_or_default();
        let (use_salt, preamble_digest) = if cache.preamble_digest.is_empty() {
            let use_salt = self.salt.is_some();
            (use_salt, preamble_hash_eth_typed(&self.name, &self.version, use_salt))
        } else {
            let new_use_salt = self.salt.is_some();
            if cache.use_salt != new_use_salt {
                (new_use_salt, preamble_hash_eth_typed(&self.name, &self.version, new_use_salt))
            } else {
                (cache.use_salt, cache.preamble_digest)
            }
        };

        let chain_id = cache.chain_id.unwrap_or(encode_u64(self.chain_id.u64()));
        let contract_addr = cache.contract_addr.unwrap_or_else(|| {
            encode_address(&self.verifying_contract)
        });

        let domain_digest = hash_eth_typed_data(
            &preamble_digest,
            &chain_id,
            &contract_addr,
            self.salt
        );
        
        Eip712DomainValues {
            chain_id,
            contract_addr,
            preamble_digest,
            domain_digest,
            use_salt,
        }

    }

}


