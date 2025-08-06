use sha2::{Digest, Sha256};
# [cfg(feature = "cosmos_arb")]
use ripemd::Ripemd160;
#[cfg(feature = "ethereum")]
use tiny_keccak::{Hasher, Keccak};



# [cfg(feature = "cosmos_arb")]
pub fn ripemd160(bytes: &[u8]) -> saa_common::Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

#[cfg(feature = "ethereum")]
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize()[0..32].try_into().unwrap()
}