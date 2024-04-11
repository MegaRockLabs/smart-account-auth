use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};
use crate::Vec;


pub fn sha256(msg: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    hasher.finalize().to_vec()
}


pub fn sha256_fixed(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut result = [0u8; 32];
    result.copy_from_slice(hasher.finalize().as_slice());
    result
}


pub fn keccak256(bytes: &[u8]) -> Vec<u8> {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output.to_vec()
}


pub fn keccak256_fixed(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}


pub fn ripemd160(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}


pub fn ripemd160_fixed(bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(bytes);
    let mut result = [0u8; 20];
    result.copy_from_slice(hasher.finalize().as_slice());
    result
}