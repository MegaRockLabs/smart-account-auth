#[cfg(feature = "wasm")]
use saa_common::cosmwasm::Api;

use saa_schema::wasm_serde;

use saa_common::{
    CredentialId, 
    AuthError,  Binary,  ToString, Verifiable, ensure
};


#[wasm_serde]
pub struct Secp256r1 {
    pub pubkey:    Binary,
    pub message:   Binary,
    pub signature: Binary,
}



impl Verifiable for Secp256r1 {

    fn id(&self) -> CredentialId {
        self.pubkey.to_vec()
    }

    fn validate(&self) -> Result<(), AuthError> {
        ensure!(self.signature.len() > 0 &&
                self.message.len() > 0 && 
                self.pubkey.len() > 0,
            AuthError::MissingData("Empty credential data".to_string())
        );
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        let res = saa_common::crypto::secp256r1_verify(
            &saa_common::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }


    #[cfg(feature = "wasm")]
    #[allow(unused_variables)]
    fn verify_cosmwasm(&self, api : &dyn Api) -> Result<(), AuthError> {

        #[cfg(all(feature = "cosmwasm_2_1", not(feature = "secretwasm")))]
        let res = api.secp256r1_verify(
            &saa_common::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        #[cfg(not(feature = "cosmwasm_2_1"))] {

            let res = implementation::secp256r1_verify(
                &saa_common::hashes::sha256(&self.message), 
                &self.signature, 
                &self.pubkey
            )?;
            ensure!(res, AuthError::Signature("Signature verification failed".to_string()));
        }
        Ok(())
    }
}



#[cfg(any(not(feature = "cosmwasm_2_1"), feature = "secretwasm"))]
mod implementation {
    use saa_common::{hashes::Identity256, AuthError};


    const ECDSA_UNCOMPRESSED_PUBKEY_LEN: usize = 65;
    const ECDSA_COMPRESSED_PUBKEY_LEN: usize = 33;


    fn check_pubkey(data: &[u8]) -> Result<(), AuthError> {
        let ok = match data.first() {
            Some(0x02) | Some(0x03) => data.len() == ECDSA_COMPRESSED_PUBKEY_LEN,
            Some(0x04) => data.len() == ECDSA_UNCOMPRESSED_PUBKEY_LEN,
            _ => false,
        };
        if ok {
            Ok(())
        } else {
            Err(AuthError::generic("Invalid public key format"))
        }
    }

    /// taken from https://github.com/CosmWasm/cosmwasm/blob/main/packages/crypto/src/secp256r1.rs
    /// to be used directly when ported to cosmwasm 2.0
    pub fn secp256r1_verify(
        message_hash: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, AuthError> {
        use  super::*;
        use digest::{Digest, Update};
        use p256::ecdsa::{Signature, VerifyingKey, signature::DigestVerifier};
        
        let message_hash : [u8; 32] = message_hash.try_into().map_err(|_| AuthError::generic("Invalid message hash"))?;
        let signature : [u8; 64] = signature.try_into().map_err(|_| AuthError::generic("Invalid signature"))?;
        check_pubkey(public_key)?;

        // Already hashed, just build Digest container
        let message_digest = Identity256::new().chain(message_hash);

        let mut signature = Signature::from_bytes(&signature.into())
            .map_err(|e| AuthError::generic(e.to_string()))?;

        // High-S signatures require normalization since our verification implementation
        // rejects them by default. If we had a verifier that does not restrict to
        // low-S only, this step was not needed.
        if let Some(normalized) = signature.normalize_s() {
            signature = normalized;
        }

        let public_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| AuthError::generic(e.to_string()))?;

        match public_key.verify_digest(message_digest, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

}

#[cfg(any(not(feature = "cosmwasm_2_1"), feature = "secretwasm"))]
pub use implementation::secp256r1_verify;