use saa_common::{
    ensure, AuthError, Binary, CredentialId, CredentialName, Identifiable, Verifiable 
};

pub use saa_common::types::exts::{
    EthTypedInfo, EthTypedPayload,
    Eip712DomainType, Eip712Domain,
    Eip712Types, Eip712Message, 
};


use saa_schema::saa_type;
use super::eip712::encode;
// use eip712::encode_data;

use saa_crypto::hashes::keccak256;

use saa_common::CredentialError::{InvalidProperty, IncorrectData};
use CredentialName::EthTypedData as EthTypedName;


use crate::eth::{typed::eip712::encode_data, utils::{encode_address, encode_u64, hash_eth_typed_data, prehash_eth_typed}};


#[saa_type]
pub struct EthTypedData {
    pub signer        :   String,

    pub signature     :   Binary,

    pub message       :   Eip712Message,

    pub domain        :   Eip712Domain,

    pub types         :   Eip712Types,
    
    #[serde(rename = "primaryType")]
    pub primary_type       :   String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_property   :   Option<String>,

    #[cfg(all(feature = "cosmwasm", target_arch = "wasm32"))]
    pub check_cw2          :   Option<bool>,

    #[serde(skip_serializing)]
    // not meant to be used by the user, instead can be read from storage for optimization
    pub cache              :   Option<EthTypedInfo>,

}




impl EthTypedData {

    fn struct_hash(&self) -> Result<[u8; 32], AuthError> {
        let tokens = encode_data(
                &self.primary_type,
                &self.message.to_value(),
                &self.types,
            )
            .map_err(|e| 
                AuthError::Crypto(e.to_string())
            )?;
            
        Ok(keccak256(&encode(&tokens)))
    }

    fn addr_hash(&self) -> Option<String> {
        self.cache
        .as_ref()
        .and_then(|c| c.addr_hash.clone())
        .or_else(|| {
            #[cfg(not(feature = "replay"))]
            return None;
            #[cfg(feature = "replay")]
            if self.message_property.is_some() && self.message.nonce.is_some() {
                self.domain.verifying_contract
                .as_ref().map(|addr| addr[2..].to_string())
            } else {
                None
            }
        })
    }

    fn pre_hash(&self) -> Vec<u8> {
        let salt_used = self.domain.salt.is_some();

        self
        .cache
        .as_ref()
        .map(|c| if c.salt_used == salt_used {
                Some(c.pre_hash.clone())
            } else {
                None
            }
        )
        .flatten()
        .unwrap_or(prehash_eth_typed(
            &self.domain.name.as_deref().unwrap_or_default(), 
            &self.domain.version.as_deref().unwrap_or_default(), 
            self.domain.salt.is_some()
        ))
    }

    fn domain_hash(
        &self,
        pre_hash: Option<Vec<u8>>,
    ) -> [u8; 32] {

        let pre_hash = pre_hash.unwrap_or(self.pre_hash());

        let chain_id = encode_u64(self.domain.chain_id
            .as_ref()
            .map(|u|u.u64())
            .unwrap_or_default()
        );
        
        let address = encode_address(self.domain.verifying_contract
            .as_deref()
            .unwrap_or_default()
        );
        
        hash_eth_typed_data(
            &pre_hash, 
            &chain_id,
            &address,
            self.domain.salt
        )
    }


    pub fn encode_eip712(
        &self,
        pre_hash: Option<Vec<u8>>,
    ) -> Result<[u8; 32], AuthError> {

        let mut digest_input = [
            &[0x19, 0x01], 
            &self.domain_hash(pre_hash)[..]
        ]
        .concat()
        .to_vec();

        if self.primary_type != "EIP712Domain" {
            digest_input.extend(
            &self.struct_hash()?
                [..]
            )
        }
        Ok(keccak256(&digest_input))
    }
    
}



impl Identifiable for EthTypedData {

    fn id(&self) -> CredentialId {
        self.signer.to_lowercase()
    }
    
    fn name(&self) -> CredentialName {
        EthTypedName
    }
}


impl Verifiable for EthTypedData {

    fn message(&self) -> std::borrow::Cow<[u8]> {
        match saa_common::to_json_binary(&self.message) {
            Ok(msg) => std::borrow::Cow::Owned(msg.into()),
            Err(_) => std::borrow::Cow::Borrowed(&[])
        }
    }


    fn validate(&self) -> Result<(), AuthError> {
        ensure!(
            self.signer.starts_with("0x"), 
            InvalidProperty(EthTypedName, "signer".into(), "must start with 0x".into())
        );
        ensure!(
            self.signature.len() >= 65, 
            InvalidProperty(EthTypedName, "signature".into(), "must be at least 65 bytes".into())
        );
        ensure!(
            hex::decode(&self.signer[2..]).map_err(|_| AuthError::Convertion("hex address".into()))?
            .len() == 20, IncorrectData(EthTypedName)
        );

        let primary_str = self.primary_type.as_str();
        let primary_types = self.types.get(primary_str)
            .ok_or_else(|| InvalidProperty(EthTypedName, "primaryType".into(), "must be in 'types'".into()))?;

            
        if self.primary_type != "EIP712Domain" {
            primary_types
            .iter()
            .try_for_each(|t| {
                ensure!(
                    self.message.contains_key(t.name.as_str()), 
                    InvalidProperty(EthTypedName, "message".into(), 
                    format!("'{}' is set to be in {} but not found in 'message'", t.name, primary_str))
                );
                Ok::<(), AuthError>(())
            })?;
        }
       
        if let Some(prop) = &self.message_property {
            ensure!(primary_str != "EIP712Domain", 
                InvalidProperty(EthTypedName, "message_property".into(), "cannot be set for EIP712Domain".into())
            );
            ensure!(
                !prop.is_empty() && (self.message.contains_key(prop) || 
                    self.message.contains_key(format!("{}s", prop).as_str())
                ),
                InvalidProperty(EthTypedName, "message_property".into(), "must be in 'message'".into())
            );
        }
        Ok(())
    }


    #[cfg(any(feature = "native", feature = "cosmwasm"))]
    fn verify(&self,
        #[cfg(feature = "cosmwasm")]
        deps: saa_common::wasm::Deps
    ) -> Result<saa_common::CredentialInfo, AuthError> {
        use saa_common::{InfoExtension, CredentialInfo, CredentialAddress};
        let pre_hash = self.pre_hash();
        #[cfg(all(feature = "cosmwasm", target_arch = "wasm32"))]
        {
            if self.check_cw2.unwrap_or_default() {
                let info = saa_common::wasm::get_contract_info(deps.storage)?;
                ensure!(
                    self.domain.name.as_deref().unwrap_or_default() == info.contract, 
                    InvalidProperty(EthTypedName, "domain.name".into(), "must match cw2".into())
                );
                ensure!(
                    self.domain.version.as_deref().unwrap_or_default() == info.version, 
                    InvalidProperty(EthTypedName, "domain.version".into(), "must match cw2".into())
                );
            }
        
        }
        let signature = &self.signature.to_vec();
        #[cfg(all(feature = "native", not(feature = "cosmwasm")))]
        let key_data = saa_crypto::secp256k1_recover_pubkey(
            &self.encode_eip712(Some(pre_hash.clone()))?, 
            &signature[..64], 
            crate::eth::utils::get_recovery_param(signature[64])?
        )?;
        #[cfg(feature = "cosmwasm")]
        let key_data = deps.api.secp256k1_recover_pubkey(
            &self.encode_eip712(Some(pre_hash.clone()))?, 
            &signature[..64], 
            crate::eth::utils::get_recovery_param(signature[64])?
        )?;
        let key_hash = saa_crypto::hashes::keccak256(&key_data[1..]);

        let addr_bytes = hex::decode(&self.signer[2..])
            .map_err(|e| AuthError::generic(e.to_string()))?;

        ensure!(addr_bytes == key_hash[12..], AuthError::RecoveryMismatch);

        let info = super::EthTypedInfo {
            pre_hash,
            salt_used: self.domain.salt.is_some(),
            addr_hash: self.addr_hash(),
        };

        Ok(CredentialInfo {
            hrp: None,
            address: Some(CredentialAddress::Evm(self.signer.clone())),
            extension: Some(InfoExtension::EthTypedData(info)),
            name: EthTypedName
        })
    }

}

