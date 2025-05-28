
#[allow(unused_imports, unused_variables, unused)]
use {super::utils::{get_recovery_param, preamble_msg_eth}, saa_common::ensure};

mod eip712;
mod credential;


pub use credential::*;


/*

impl Verifiable for EthTypedData {

    fn id(&self) -> CredentialId {
        self.signer.to_string()
    }


    fn validate(&self) -> Result<(), AuthError> {
        if !self.signer.starts_with("0x") {
            return Err(AuthError::MissingData("Ethereum `signer` address must start with 0x".to_string()));
        }
        if self.signature.len() < 65 {
            return Err(AuthError::MissingData("Signature must be at least 65 bytes".to_string()));
        }
        let signer_bytes = hex::decode(&self.signer[2..])
            .map_err(|e| AuthError::generic(e.to_string()))?;

        if signer_bytes.len() != 20 {
            return Err(AuthError::MissingData("Signer must be 20 bytes".to_string()));
        }
        Ok(())
    }


    #[cfg(feature = "native")] 
    fn verify(&self) -> Result<(), AuthError> {
        let signature = &self.signature.to_vec();
        let key_data = saa_crypto::secp256k1_recover_pubkey(
            &preamble_msg_eth(&self.message), 
            &signature[..64], 
            get_recovery_param(signature[64])?
        )?;
        let hash = saa_crypto::hashes::keccak256(&key_data[1..]);

        let addr_bytes = hex::decode(&self.signer[2..])
        .map_err(|e| AuthError::generic(e.to_string()))?;
    
        ensure!(addr_bytes == hash[12..], AuthError::RecoveryMismatch);
        
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&self, api: &dyn saa_common::wasm::Api) -> Result<(), AuthError> {
        
        let signature = &self.signature.to_vec();
        
        let key_data = api.secp256k1_recover_pubkey(
            &preamble_msg_eth(&self.message), 
            &signature[..64], 
            get_recovery_param(signature[64])?
        )?;
    
        let hash = saa_crypto::hashes::keccak256(&key_data[1..]);

        let addr_bytes = hex::decode(&self.signer[2..])
            .map_err(|e| AuthError::generic(e.to_string()))?;
        
        ensure!(addr_bytes == hash[12..], AuthError::RecoveryMismatch);

        Ok(())
    }


}


 */


 
// use alloy::dyn_abi::{Eip712Types, Eip712Domain, TypedData, TypeDef};


