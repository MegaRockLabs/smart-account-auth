use bech32::{ToBase32, Variant};
use saa_common::{
    hashes::{keccak256_fixed, ripemd160, sha256}, 
    AuthError, AddressError
};


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


pub fn derive_addr(hrp: &str, pubkey_bytes: &[u8]) -> Result<String, AddressError> {
    let address_bytes = ripemd160(&sha256(pubkey_bytes));
    let address_str = bech32::encode(hrp, address_bytes.to_base32(), Variant::Bech32);

    match address_str {
        Ok(s) => Ok(s),
        Err(err) => Err(err.into()),
    }
}



