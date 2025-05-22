use {saa_common::Vec, sha2::{Digest, Sha256}};
# [cfg(feature = "cosmwasm")]
use ripemd::Ripemd160;
#[cfg(feature = "ethereum")]
use tiny_keccak::{Hasher, Keccak};


pub fn sha256(msg: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    hasher.finalize().to_vec()
}

# [cfg(feature = "cosmwasm")]
pub fn ripemd160(bytes: &[u8]) -> Vec<u8> {
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