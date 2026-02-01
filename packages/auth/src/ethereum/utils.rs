use saa_common::{AuthError, vec, format};
use saa_crypto::hashes::keccak256;


pub fn get_recovery_param(v: u8) -> Result<u8, AuthError> {
    match v {
        27 => Ok(0),
        28 => Ok(1),
        _ => Err(AuthError::RecoveryParam)
    }
}


#[cfg(feature = "eth_personal")]
pub fn hash_eth_personal(msg: &[u8]) -> [u8; 32] {
    const PREFIX: &str = "\x19Ethereum Signed Message:\n";
    let mut bytes = vec![];
    bytes.extend_from_slice(PREFIX.as_bytes());
    let len_str = format!("{}", msg.len());
    bytes.extend_from_slice(len_str.as_bytes());
    bytes.extend_from_slice(msg);
    keccak256(&bytes)
}





#[cfg(feature = "eth_typed_data")]
pub fn prehash_eth_typed(name: &str, version: &str, salt: bool) -> Vec<u8> {
    let name_hash = keccak256(name.as_bytes());
    let version_hash = keccak256(version.as_bytes());
    let domain_type = if salt {
        EIP712_DOMAIN_TYPE_HASH_WITH_SALT
    } else {
        EIP712_DOMAIN_TYPE_HASH
    };
    // Preallocate exact capacity (96 = 32 * 3)
    let mut result = Vec::with_capacity(96);
    result.extend_from_slice(&domain_type);
    result.extend_from_slice(&name_hash);
    result.extend_from_slice(&version_hash);
    result
}


#[cfg(feature = "eth_typed_data")]
pub fn hash_eth_typed_data(
    preamble_hash: &[u8],
    chain_id: &[u8],
    contract_addr: &[u8],
    salt: &Option<Vec<u8>>,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(match salt {
        Some(_) => 128,
        None => 96,
    });
    data.extend_from_slice(preamble_hash);
    data.extend_from_slice(&chain_id);
    data.extend_from_slice(&contract_addr);
    if let Some(s) = salt {
        data.extend_from_slice(&s);
    }
    keccak256(&data)
}



pub(crate) fn encode_address(addr_hex: &str) -> [u8; 32] {
    let addr = hex::decode(addr_hex.trim_start_matches("0x")).expect("Invalid hex address");
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&addr); // Right-align address
    out
}

pub(crate) fn encode_u64(value: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&value.to_be_bytes()); // Right-align
    buf
}


/// Pre-computed value of the following expression:
///
/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address
/// verifyingContract)")`
const EIP712_DOMAIN_TYPE_HASH: [u8; 32] = [
    139, 115, 195, 198, 155, 184, 254, 61, 81, 46, 204, 76, 247, 89, 204, 121, 35, 159, 123, 23,
    155, 15, 250, 202, 169, 167, 93, 82, 43, 57, 64, 15,
];

const EIP712_DOMAIN_TYPE_HASH_WITH_SALT: [u8; 32] = [
    216, 124, 214, 239, 121, 212, 226, 185, 94, 21, 206, 138, 191, 115, 45, 181, 30, 199, 113, 241,
    202, 46, 220, 207, 34, 164, 108, 114, 154, 197, 100, 114,
];

