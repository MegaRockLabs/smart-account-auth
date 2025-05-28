use saa_common::AuthError;
use saa_crypto::hashes::keccak256;
use ethers_core::{types::transaction::eip712, abi::encode};
use std::collections::BTreeMap;
use eip712::encode_data;

use serde::{Deserialize, Serialize};
use serde_json::{Value, Map};


pub use eip712::{EIP712Domain, Types}; 

pub type Message = BTreeMap<String, Value>;


// use eip712::{TypedData};


// at the moment is a dummy copy of personal sign
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthTypedData {
    /// Signing domain metadata. The signing domain is the intended context for the signature (e.g.
    /// the dapp, protocol, etc. that it's intended for). This data is used to construct the domain
    /// seperator of the message.
    pub domain: EIP712Domain,
    /// The custom types used by this message.
    pub types: Types,
    #[serde(rename = "primaryType")]
    /// The type of the message.
    pub primary_type: String,
    /// The message to be signed.
    pub message: Message,
}



impl EthTypedData {

    fn struct_hash(&self) -> Result<[u8; 32], AuthError> {
        let tokens = encode_data(
            &self.primary_type,
            &Value::Object(Map::from_iter(self.message.clone())),
            &self.types,
        )?;
        Ok(keccak256(&encode(&tokens)))
    }
    
    pub fn encode_eip712(&self) -> Result<[u8; 32], AuthError> {
        let domain_separator = self.domain.separator();
        let mut digest_input = [&[0x19, 0x01], &domain_separator[..]].concat().to_vec();

        if self.primary_type != "EIP712Domain" {
            // compatibility with <https://github.com/MetaMask/eth-sig-util>
            digest_input.extend(&self.struct_hash()?[..])
        }
        Ok(keccak256(&digest_input))
    }

}