use saa_common::AuthError;

use digest::{
    FixedOutput, HashMarker, Output, OutputSizeUser, Reset, Update,
    consts::U32, generic_array::GenericArray,
};

// Copied from `cosmwasm_crypto` [here](https://github.com/CosmWasm/cosmwasm/tree/main/packages/crypto)
#[derive(Clone, Default)]
pub struct Identity256 {
    array: GenericArray<u8, U32>,
}

impl Update for Identity256 {
    fn update(&mut self, hash: &[u8]) {
        assert_eq!(hash.as_ref().len(), 32);
        self.array = *GenericArray::from_slice(hash);
    }
}
impl OutputSizeUser for Identity256 {
    type OutputSize = U32;
}

impl FixedOutput for Identity256 {
    fn finalize_into(self, out: &mut Output<Self>) {
        *out = self.array;
    }
}

impl HashMarker for Identity256 {}

impl Reset for Identity256 {
    fn reset(&mut self) {
        *self = Self::default();
    }
}



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