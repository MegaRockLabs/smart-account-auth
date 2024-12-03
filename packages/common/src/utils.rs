use crate::{hashes::{ripemd160, sha256}, AuthError, String};
use bech32::{hrp::Hrp, Bech32};


#[cfg(feature = "wasm")]
pub fn new_cw_binary(data: Vec<u8>) -> crate::cosmwasm::Binary {
    return data.into();
}


pub fn prefix_from_address(address: &str) -> String {
    address.split("1").next().unwrap().to_string()
}


pub fn pubkey_to_address(pubkey: &[u8], hrp: &str) -> Result<String, AuthError> {
    let base32_addr = ripemd160(&sha256(pubkey));
    let account: String = bech32::encode::<Bech32>(Hrp::parse(hrp)?, &base32_addr)?;
    Ok(account)
}


#[cfg(feature = "wasm")]
pub fn pubkey_to_canonical(pubkey: &[u8]) -> crate::cosmwasm::CanonicalAddr {
    crate::cosmwasm::CanonicalAddr::from(ripemd160(&sha256(pubkey))).into()
}


