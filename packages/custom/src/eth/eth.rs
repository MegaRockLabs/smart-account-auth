#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env};

#[cfg(feature = "native")] 
use saa_common::crypto::secp256k1_recover_pubkey;

use saa_schema::wasm_serde;

use saa_common::{
    hashes::keccak256, ensure,CredentialId, 
    AuthError, Binary, String, ToString, Verifiable 
};

use super::utils::{get_recovery_param, preamble_msg_eth};


#[wasm_serde]
pub struct EthPersonalSign {
    pub message:   Binary,
    pub signature: Binary,
    pub signer:    String,
}


impl Verifiable for EthPersonalSign {

    fn id(&self) -> CredentialId {
        self.signer.as_bytes().to_vec()
    }

    fn hrp(&self) -> Option<String> {
        #[cfg(feature = "injective")]
        if true {
            return Some("inj".to_string());
        }
        None
    }

    fn validate(&self) -> Result<(), AuthError> {
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
        let signature = &self.signature.0;
        let key_data = secp256k1_recover_pubkey(
            &preamble_msg_eth(
                &Binary(hex::encode(&self.message).into())
            ), 
            &signature[..64], 
            get_recovery_param(signature[64])?
        )?;
        let hash = keccak256(&key_data[1..]);
        let recovered = String::from_utf8(
            hash[12..].to_vec()
        ).map_err(|_| AuthError::RecoveryMismatch)?;
    
        ensure!(self.signer == recovered, AuthError::RecoveryMismatch);
        Ok(())
    }

/*     let key_data = api.secp256k1_recover_pubkey(
        &preamble_msg_eth(&Binary(
            hex::encode(&self.message).into()
        )), 
        &signature[..64], 
        get_recovery_param(signature[64])?
    )?;
 */

    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&self, api: &dyn Api, _: &Env) -> Result<(), AuthError> {
        
        let signature = &self.signature.0;
        
        let key_data = api.secp256k1_recover_pubkey(
            &preamble_msg_eth(
                &Binary(hex::encode(&self.message).into())
            ), 
            &signature[..64], 
            get_recovery_param(signature[64])?
        )?;
    
        let hash = keccak256(&key_data[1..]);

        let addr_bytes = hex::decode(&self.signer[2..])
            .map_err(|e| AuthError::generic(e.to_string()))?;
        
        let hash_hex = hex::encode(&hash[12..]);
        let addr_hex = hex::encode(&addr_bytes);
        println!("hash: {:?}", hash_hex);
        println!("addr: {:?}", addr_hex);
        
        ensure!(addr_bytes == hash[12..], AuthError::RecoveryMismatch);
        Ok(())
    }


}

