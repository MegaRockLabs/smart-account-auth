use saa_common::{
    CredentialId, CredentialName, Identifiable, Verifiable,
    AuthError, Binary,
    ensure, 
};

pub use saa_common::types::exts::{
    EthTypedInfo, EthTypedPayload,
    Eip712DomainType, Eip712Domain,
    Eip712Types, Eip712Message, 
};


use serde_json::{Value, Map};
use ethers_core::{types::transaction::eip712, abi::encode};
use eip712::encode_data;

use saa_crypto::hashes::keccak256;
use saa_schema::saa_type;

use saa_common::CredentialError::{InvalidProperty, IncorrectData};
use CredentialName::EthTypedData as EthTypedName;

use crate::eth::utils::{encode_address, encode_u64, hash_eth_typed_data, prehash_eth_typed};


#[saa_type]
pub struct EthTypedData {
    pub signer        :   String,

    pub signature     :   Binary,

    pub message       :   Eip712Message,

    pub domain        :   Eip712Domain,

    pub types         :   Eip712Types,
    
    #[serde(rename = "primaryType")]
    pub primary_type  :   String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_property   :   Option<String>
}




//  local   BTreeMap<String, Vec<Eip712DomainType>>; with local Eip712DomainType
//  to ext  BTreeMap<String, Vec<eip712::Eip712DomainType>>; with ext eip712::Eip712DomainType

fn types_to_types(
    types: &Eip712Types
) -> eip712::Types {
    types
    .iter()
    .map(|(k, v)| 
        (k.clone(), v.iter()
                    .map(|t| t.clone().into())
                    .collect()
        )
    ).collect()
}


impl EthTypedData {

    fn struct_hash(&self) -> Result<[u8; 32], AuthError> {
        let tokens = encode_data(
            &self.primary_type,
            &Value::Object(Map::from_iter(self.message.clone())),
            &types_to_types(&self.types),
        )
        .map_err(|e| AuthError::generic(e.to_string()))?;
        Ok(keccak256(&encode(&tokens)))
    }

    pub fn domain_hash(
        &self,
    ) -> [u8; 32] {
        
        let pre_hash = prehash_eth_typed(
            &self.domain.name.as_deref().unwrap_or_default(), 
            &self.domain.version.as_deref().unwrap_or_default(), 
            self.domain.salt.is_some()
        );

        let chain_id = encode_u64(self.domain.chain_id
            .as_ref()
            .map(|u|u.u64())
            .unwrap_or_default());
        let address = encode_address(self.domain.verifying_contract
            .as_deref()
            .unwrap_or_default());
        
        hash_eth_typed_data(
            &pre_hash, 
            &chain_id,
            &address,
            self.domain.salt
        )
    }


    pub fn encode_eip712(&self) -> Result<[u8; 32], AuthError> {
        let mut digest_input = [&[0x19, 0x01], &self.domain_hash()[..]].concat().to_vec();
        //let mut digest_input = [&[0x19, 0x01], &self.domain_hash()[..]].concat().to_vec();
        if self.primary_type != "EIP712Domain" {
            digest_input.extend(&self.struct_hash()?[..])
        }
        Ok(keccak256(&digest_input))
    }
    
}

/* 

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

        println!("Chain ID: {:?}", chain_id);
        println!("Chain Id to be: {:?}", self.chain_id.u64().to_be_bytes());
        println!("Chain ID to le: {:?}", self.chain_id.u64().to_le_bytes());
        println!("Chain ID to str bytes: {:?}", self.chain_id.to_string().as_bytes());

        let domain_digest = hash_eth_typed_data(
            &preamble_digest,
            &self.chain_id.to_string().as_bytes(),
            &contract_addr,
           Some([2;32])
        );
        
        Eip712DomainValues {
            chain_id,
            contract_addr,
            preamble_digest,
            domain_digest,
            use_salt,
        }

    }
    
} */



impl Identifiable for EthTypedData {
    fn id(&self) -> CredentialId {
        self.signer.clone()
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
            hex::decode(&self.signer[2..]).map_err(|_| AuthError::Convertation("hex address".into()))?
            .len() == 20, IncorrectData(EthTypedName)
        );
        ensure!(
            self.types.contains_key(self.primary_type.as_str()),
            InvalidProperty(EthTypedName, "primaryType".into(), "must be a valid type in types".into()
        ));
        Ok(())
    }


    #[cfg(any(feature = "native", feature = "cosmwasm"))]
    fn verify(&self,
        #[cfg(feature = "cosmwasm")]
        deps: saa_common::wasm::Deps
    ) -> Result<saa_common::CredentialInfo, AuthError> {
        use saa_common::{InfoExtension, CredentialInfo};
        #[cfg(all(feature = "cosmwasm", target_arch = "wasm32"))]
        {
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
        let signature = &self.signature.to_vec();
        #[cfg(all(feature = "native", not(feature = "cosmwasm")))]
        let key_data = saa_crypto::secp256k1_recover_pubkey(
            &self.encode_eip712()?, 
            &signature[..64], 
            crate::eth::utils::get_recovery_param(signature[64])?
        )?;
        #[cfg(feature = "cosmwasm")]
        let key_data = deps.api.secp256k1_recover_pubkey(
            &self.encode_eip712()?, 
            &signature[..64], 
            crate::eth::utils::get_recovery_param(signature[64])?
        )?;
        let key_hash = saa_crypto::hashes::keccak256(&key_data[1..]);

        let addr_bytes = hex::decode(&self.signer[2..])
            .map_err(|e| AuthError::generic(e.to_string()))?;

        ensure!(addr_bytes == key_hash[12..], AuthError::RecoveryMismatch);

        // let options = self.cache_options.clone().unwrap_or_default(); 
        // let save_types = options.types.unwrap_or(false);

        let info = super::EthTypedInfo {
            // primary_type: if save_types { Some(self.primary_type.to_string())} else { None },
            // types: if save_types { Some(to_json_binary(&self.types)? ) } else { None },
        };
        Ok(CredentialInfo {
            hrp: None,
            address: None,
            extension: Some(InfoExtension::EthTypedData(info)),
            name: EthTypedName
        })
    }

}

