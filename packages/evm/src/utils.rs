use saa_common::{hashes::keccak256_fixed, AuthError};

pub fn preamble_msg(msg: &[u8]) -> [u8; 32] {
    const PREFIX: &str = "\x19Ethereum Signed Message:\n";

    let mut bytes = vec![];
    bytes.extend_from_slice(PREFIX.as_bytes());
    bytes.extend_from_slice(msg.len().to_string().as_bytes());
    bytes.extend_from_slice(msg);

    keccak256_fixed(&bytes)
}


pub fn get_recovery_param(v: u8) -> Result<u8, AuthError> {
    match v {
        27 => Ok(0),
        28 => Ok(1),
        _ => Err(AuthError::RecoveryParam)
    }
}
