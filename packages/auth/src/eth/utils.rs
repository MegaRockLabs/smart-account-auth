use saa_common::{hashes::keccak256, AuthError, vec, format};


pub fn preamble_msg_eth(msg: &[u8]) -> [u8; 32] {
    const PREFIX: &str = "\x19Ethereum Signed Message:\n";
    let mut bytes = vec![];
    bytes.extend_from_slice(PREFIX.as_bytes());
    let len_str = format!("{}", msg.len());
    bytes.extend_from_slice(len_str.as_bytes());
    bytes.extend_from_slice(msg);
    keccak256(&bytes)
}



pub fn get_recovery_param(v: u8) -> Result<u8, AuthError> {
    match v {
        27 => Ok(0),
        28 => Ok(1),
        _ => Err(AuthError::RecoveryParam)
    }
}
