use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};


pub fn sha256(msg: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    hasher.finalize().to_vec()
}


pub fn ripemd160(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
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



/* pub fn derive_addr(hrp: &str, pubkey_bytes: &[u8]) -> Result<String, AddressError> {
    let address_bytes = ripemd160(&sha256(pubkey_bytes));
    let address_str = bech32::encode(hrp, address_bytes.to_base32(), Variant::Bech32);

    match address_str {
        Ok(s) => Ok(s),
        Err(err) => Err(err.into()),
    }
} */