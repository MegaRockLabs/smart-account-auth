use crate::{AuthError, Binary, String, Uint64};
use std::collections::BTreeMap;
use saa_schema::saa_type;
use schemars::JsonSchema;
use serde_json::Value;

pub type Eip712Types    =  BTreeMap<String, Vec<Eip712DomainType>>;
// pub type Eip712Message  =  BTreeMap<String, Value>;
// use serde_json::Value


#[cfg_attr(not(feature = "wasm"), derive(serde::Serialize, serde::Deserialize))]
#[saa_type(no_deny)]
#[non_exhaustive]
pub struct Eip712MessageProps {}


#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct Eip712Message {
    pub nonce: Option<Uint64>,

    #[serde(flatten)]
    pub props: BTreeMap<Value, Value>,
}


impl Eip712Message {

    pub fn contains_key(&self, key: &str) -> bool {
        key == "nonce" || self.props.contains_key(&Value::String(key.to_string()))
    }

    pub fn get(&self, key: &str) -> Option<Value> {
        self.props.get(&Value::String(key.to_string()))
            .cloned()
    }

    pub fn gets(&self, key: &str) -> Option<Vec<Value>> {
        self.props.get(&Value::String(format!("{}s", key)))
            .and_then(|value| match value {
                Value::Seq(arr) => Some(arr.clone()),
                _ => None,
            })
    }

    pub fn is_empty(&self) -> bool {
        self.props.is_empty() && self.nonce.is_none()
    }

    pub fn to_value(&self) -> Value {
        let mut map = BTreeMap::<Value, Value>::new();
        for (key, value) in &self.props {
            map.insert(key.clone(), value.clone());
        }
        if let Some(nonce) = self.nonce {
            map.insert(Value::String("nonce".into()), Value::String(nonce.to_string()));
        }
        Value::Map(map)
    }

    pub fn to_string(&self) -> Result<String, AuthError> {
        crate::to_json_string(&self.to_value())
            .map_err(|e| AuthError::generic(e.to_string()))
    }

    pub fn to_binary(&self) -> Result<Binary, AuthError> {
        crate::to_json_binary(&self.to_value())
            .map_err(|e| AuthError::generic(e.to_string()))
    }
}


impl JsonSchema for Eip712Message {
    fn schema_name() -> String {
        "Eip712Message".to_string()
    }

    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some("EIP-712 message structure".to_string()),
                ..Default::default()
            })),
            instance_type: Some(schemars::schema::SingleOrVec::Single(Box::new(
                schemars::schema::InstanceType::Object)
            )),
            ..Default::default()
        })
    }
}

#[cfg_attr(not(feature = "wasm"), derive(serde::Serialize, serde::Deserialize))]
#[saa_type]
pub struct Eip712DomainType {
    pub name: String,
    #[serde(rename = "type")]
    pub r#type: String,
}




#[cfg_attr(not(feature = "wasm"), derive(serde::Serialize, serde::Deserialize))]
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




#[cfg_attr(not(feature = "wasm"), derive(serde::Serialize, serde::Deserialize))]
#[saa_type]
pub struct EthTypedInfo {
    pub addr_hash   :  Option<String>,
    pub pre_hash    :  Vec<u8>,
    pub salt_used   :  bool,
}



#[saa_type(no_deny)]
#[non_exhaustive]
pub struct EthTypedPayload {
    pub types            :  Option<Eip712Types>,
    pub primary_type     :  Option<String>,
    pub message_property :  Option<String>,
    
    pub domain           :  Option<Eip712Domain>,
    pub contract_addr    :  Option<String>,
    pub salt             :  Option<Binary>
}





