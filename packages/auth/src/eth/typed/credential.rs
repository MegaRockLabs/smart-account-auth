use saa_common::{ensure, types::exts::EthTypedSaveOptions, AuthError, Binary, CredentialId, CredentialName, Identifiable, Verifiable
};

use serde_json::{Value, Map};
use ethers_core::{types::transaction::eip712, abi::encode};
use eip712::encode_data;

use saa_crypto::hashes::keccak256;
use saa_schema::saa_type;
use crate::eth::utils::hash_eth_typed_data;

use super::eip712::*; 

use saa_common::CredentialError::{InvalidProperty, IncorrectData, NoInfoProperty};
use CredentialName::EthTypedData as EthTypedName;


#[saa_type]
pub struct EthTypedData {
    pub signer        :   String,

    pub signature     :   Binary,

    pub message       :   Eip712Message,

    pub domain        :   Option<Eip712Domain>,

    pub types         :   Eip712Types,
    
    #[serde(rename = "primaryType")]
    pub primary_type  :   String,

    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_options :   Option<EthTypedSaveOptions>,


    #[serde(skip_serializing)]
    pub cache         :   Option<super::EthTypedCache>

}


//  local   BTreeMap<String, Vec<Eip712DomainType>>; with local Eip712DomainType
//  to ext  BTreeMap<String, Vec<eip712::Eip712DomainType>>; with ext eip712::Eip712DomainType

fn types_to_types(
    types: &Eip712Types
) -> eip712::Types {
    types
    .iter()
    .map(|(k, v)| 
        (k.clone(), v.iter().map(|t| t.clone().into()).collect())
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

    pub fn compute_domain_values(
        &self
    ) -> Result<Eip712DomainValues, AuthError> {
        let cache = self.cache.clone();
        if let Some(domain) = &self.domain {
            return Ok(domain.compute_values(cache));
        }

        let cache = cache.ok_or_else(|| IncorrectData(EthTypedName))?;
        ensure!(!cache.preamble_digest.is_empty(), NoInfoProperty(EthTypedName, "cache.preamble_digest".into()));
        let chain_id = cache.chain_id.ok_or_else(|| NoInfoProperty(EthTypedName, "cache.chain_id".into()))?;
        let contract_addr = cache.contract_addr.ok_or_else(|| NoInfoProperty(EthTypedName, "cache.contract_addr".into()))?;

        let domain_digest = match cache.domain_digest {
            Some(digest) => digest,
            None => hash_eth_typed_data(
                cache.preamble_digest.as_slice(),
                &chain_id,
                &contract_addr,
                None
            )
        };

        Ok(Eip712DomainValues {
            chain_id,
            contract_addr,
            domain_digest,
            preamble_digest: cache.preamble_digest,
            use_salt: cache.use_salt,
        })
    }


    pub fn encode_eip712(
        &self,
        domain_hash: &[u8]
    ) -> Result<[u8; 32], AuthError> {
        let mut digest_input = [&[0x19, 0x01], domain_hash].concat().to_vec();
        if self.primary_type != "EIP712Domain" {
            digest_input.extend(&self.struct_hash()?[..])
        }
        Ok(keccak256(&digest_input))
    }
    
}



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
        Ok(())
    }


    #[cfg(any(feature = "native", feature = "cosmwasm"))]
    fn verify(&self,
        #[cfg(feature = "cosmwasm")]
        deps: saa_common::wasm::Deps
    ) -> Result<saa_common::CredentialInfo, AuthError> {
        use saa_common::InfoExtension;
        let signature = &self.signature.to_vec();
        let values = self.compute_domain_values()?;
        #[cfg(all(feature = "native", not(feature = "cosmwasm")))]
        let key_data = saa_crypto::secp256k1_recover_pubkey(
            &self.encode_eip712(&values.domain_digest)?, 
            &signature[..64], 
            crate::eth::utils::get_recovery_param(signature[64])?
        )?;
        #[cfg(feature = "cosmwasm")]
        let key_data = deps.api.secp256k1_recover_pubkey(
            &self.encode_eip712(&values.domain_digest)?, 
            &signature[..64], 
            crate::eth::utils::get_recovery_param(signature[64])?
        )?;
        let key_hash = saa_crypto::hashes::keccak256(&key_data[1..]);

        let addr_bytes = hex::decode(&self.signer[2..])
            .map_err(|e| AuthError::generic(e.to_string()))?;

        ensure!(addr_bytes == key_hash[12..], AuthError::RecoveryMismatch);


        let options = self.cache_options.clone().unwrap_or_default(); 
        let save_types = options.types.unwrap_or(false);

        let info = super::EthTypedInfo {
            primary_type: if save_types { Some(self.primary_type.clone())} else { None },
            types: if save_types { Some(saa_common::to_json_binary(&self.types)? ) } else { None },
            cache: values.to_cached(options)
        };

        Ok(saa_common::CredentialInfo {
            hrp: None,
            address: None,
            extension: Some(InfoExtension::EthTypedData(info)),
            name: EthTypedName
        })
    }

}

