
use ed25519_zebra::{
    VerificationKey,
     Signature as Ed25519Signature
};

use k256::ecdsa::{
    signature::DigestVerifier,
    VerifyingKey, RecoveryId,
    Signature as Secp256k1Signature
};

use digest::{Digest, Update};
use crate::{digest::Identity256, AuthError}; 


fn read_hash(data: &[u8]) -> Result<[u8; 64], AuthError> {
    data.try_into().map_err(|_| AuthError::Crypto("Invalid hash".to_string()))
}

fn read_signature(data: &[u8]) -> Result<[u8; 64], AuthError> {
    data.try_into().map_err(|_| AuthError::Crypto("Invalid signature".to_string()))
}

fn read_pubkey(data: &[u8]) -> Result<[u8; 32], AuthError> {
    data.try_into().map_err(|_| AuthError::Crypto("Invalid pubkey".to_string()))
}

fn check_pubkey(data: &[u8]) -> Result<(), AuthError> {
    let ok = match data.first() {
        Some(0x02) | Some(0x03) => data.len() == 33,
        Some(0x04) => data.len() == 65,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(AuthError::Crypto("Invalid pubkey".to_string()))
    }
}



pub fn ed25519_verify(
    message:    &[u8], 
    signature:  &[u8], 
    public_key: &[u8]
) -> Result<bool, AuthError> {
    let signature = read_signature(signature)?;
    let pubkey = read_pubkey(public_key)?;

    match VerificationKey::try_from(pubkey)
        .and_then(|vk| vk.verify(&Ed25519Signature::from(signature), message))
    {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}


pub fn secp256k1_verify(
    message_hash: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, AuthError> {
    let message_hash = read_hash(message_hash)?;
    let signature = read_signature(signature)?;
    check_pubkey(public_key)?;

    // Already hashed, just build Digest container
    let message_digest = Identity256::new().chain(message_hash);

    let mut signature = Secp256k1Signature::from_bytes(&signature.into())
        .map_err(|e| AuthError::Generic(e.to_string()))?;

  
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
    }

    let public_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| AuthError::Generic(e.to_string()))?;

    match public_key.verify_digest(message_digest, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}


pub fn secp256k1_recover_pubkey(
    message_hash: &[u8],
    signature: &[u8],
    recovery_param: u8,
) -> Result<Vec<u8>, AuthError> {
    let message_hash = read_hash(message_hash)?;
    let signature = read_signature(signature)?;

    // params other than 0 and 1 are explicitly not supported
    let id = match recovery_param {
        0 => RecoveryId::new(false, false),
        1 => RecoveryId::new(true, false),
        _ => return Err(AuthError::Recovery("Invalid recovery params".to_string())),
    };

    // Compose extended signature
    let signature = Secp256k1Signature::from_bytes(&signature.into())
        .map_err(|e| AuthError::Crypto(e.to_string()))?;

    // Recover
    let message_digest = Identity256::new().chain(message_hash);
    let pubkey = VerifyingKey::recover_from_digest(message_digest, &signature, id)
        .map_err(|e| AuthError::Crypto(e.to_string()))?;
    let encoded: Vec<u8> = pubkey.to_encoded_point(false).as_bytes().into();
    Ok(encoded)
}
