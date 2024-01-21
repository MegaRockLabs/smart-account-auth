#[cfg(feature = "cosmwasm")]
use cosmwasm_std::{Api, Env, MessageInfo};

use saa_common::{
    AuthError, Verifiable, CredentialId, 
    cosmwasm_crypto::secp256k1_recover_pubkey,
    hashes::keccak256_fixed, 
};
use saa_schema::wasm_serde;
use super::utils::{get_recovery_param, preamble_msg_eth};

#[wasm_serde]
pub struct EvmCredential {
    pub message:   Vec<u8>,
    pub signature: Vec<u8>,
    pub signer:    Vec<u8>,
}


impl Verifiable for EvmCredential {

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
        let key_data = secp256k1_recover_pubkey(
            &preamble_msg_eth(&self.message), 
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
    fn verify_cosmwasm(&mut self, api: &dyn Api, _: &Env, _: &MessageInfo) -> Result<(), AuthError> {

        let key_data = api.secp256k1_recover_pubkey(
            &preamble_msg_eth(&self.message), 
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

