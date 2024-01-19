use bech32::{ToBase32, Variant};

use saa_common::{
    hashes::{ripemd160, sha256}, 
    AddressError
};


pub fn derive_addr(hrp: &str, pubkey_bytes: &[u8]) -> Result<String, AddressError> {
    let address_bytes = ripemd160(&sha256(pubkey_bytes));
    let address_str = bech32::encode(hrp, address_bytes.to_base32(), Variant::Bech32);

    match address_str {
        Ok(s) => Ok(s),
        Err(err) => Err(err.into()),
    }
}

