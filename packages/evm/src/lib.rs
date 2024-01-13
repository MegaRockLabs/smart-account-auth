#[cfg(feature = "cosmwasm")]
use cosmwasm_std::Api;

use saa_common::{AuthError, Credential, CredentialId, hashes::keccak256_fixed};
use cosmwasm_crypto::secp256k1_recover_pubkey;
use saa_macros::wasm_serde;
use utils::{
    get_recovery_param, 
    preamble_msg
};



#[wasm_serde]
pub struct EvmCredential {
    pub message:   Vec<u8>,
    pub signature: Vec<u8>,
    pub signer:    Vec<u8>,
}



impl Credential for EvmCredential {

    fn id(&self) -> CredentialId {
        self.signer.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {

        if self.signature.len() < 65 {
            return Err(AuthError::InvalidLength("Signature must be at least 65 bytes".to_string()));
        }
    
        if self.signer.len() != 20 {
            return Err(AuthError::InvalidLength("Signer must be 20 bytes".to_string()));
        }
    
        Ok(())
    }

    fn verify(&self) -> Result<(), AuthError> {
        self.validate()?;
    
        let key_data = secp256k1_recover_pubkey(
            &preamble_msg(&self.message), 
            &self.signature[..64], 
            get_recovery_param(self.signature[64])?
        )?;
    
        let hash = keccak256_fixed(&key_data[1..]);
        let recovered = &hash[12..];
    
        if self.signer == recovered {
            Ok(())
        } else {
            Err(AuthError::RecoveryMismatch)
        }
    }

    #[cfg(feature = "cosmwasm")]
    fn verify_api_cosmwasm(&self, api: &dyn Api) -> Result<(), AuthError> {
        self.validate()?;
    
        let key_data = api.secp256k1_recover_pubkey(
            &preamble_msg(&self.message), 
            &self.signature[..64], 
            get_recovery_param(self.signature[64])?
        )?;
    
        let hash = keccak256_fixed(&key_data[1..]);
        let recovered = &hash[12..];
    
        if self.signer == recovered {
            Ok(())
        } else {
            Err(AuthError::RecoveryMismatch)
        }
    }
}



#[cfg(test)]
mod tests;
pub mod utils;