
#[cfg(any(feature = "cosmwasm", feature = "native"))]
use {super::utils::{get_recovery_param, preamble_msg_eth}, saa_common::ensure};
use saa_common::{CredentialId, CredentialName, CredentialInfo, AuthError, Binary, String, ToString, Verifiable };


#[saa_schema::saa_type]
pub struct EthPersonalSign {
    pub message:   Binary,
    pub signature: Binary,
    pub signer:    String,
}


impl Verifiable for EthPersonalSign {

    fn id(&self) -> CredentialId {
        //format!("0x{}", self.signer.to_lowercase())
        self.signer.to_string()
    }

    fn message(&self) -> std::borrow::Cow<[u8]> {
        std::borrow::Cow::Borrowed(self.message.as_slice())
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

    #[cfg(any(feature = "native", feature = "cosmwasm"))]
    fn verify(&self,
        #[cfg(feature = "cosmwasm")]
        deps: saa_common::wasm::Deps
    ) -> Result<CredentialInfo, AuthError> {
        let signature = &self.signature.to_vec();
        #[cfg(all(feature = "native", not(feature = "cosmwasm")))]
        let key_data = saa_crypto::secp256k1_recover_pubkey(
            &preamble_msg_eth(&self.message), 
            &signature[..64], 
            get_recovery_param(signature[64])?
        )?;
        #[cfg(feature = "cosmwasm")]
        let key_data = deps.api.secp256k1_recover_pubkey(
            &preamble_msg_eth(&self.message), 
            &signature[..64], 
            get_recovery_param(signature[64])?
        )?;
        let hash = saa_crypto::hashes::keccak256(&key_data[1..]);

        let addr_bytes = hex::decode(&self.signer[2..])
            .map_err(|e| AuthError::generic(e.to_string()))?;
        
        ensure!(addr_bytes == hash[12..], AuthError::RecoveryMismatch);
        Ok(CredentialInfo {
            hrp: None,
            address: None,
            extension: None,
            name: CredentialName::EthPersonalSign,
        })
    }



}

