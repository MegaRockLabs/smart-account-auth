use crate::{hashes::{ripemd160, sha256}, AuthError, String};
use bech32::{hrp::Hrp, Bech32};


pub fn pubkey_to_address(pubkey: &[u8], hrp: &str) -> Result<String, AuthError> {
    let base32_addr = ripemd160(&sha256(pubkey));
    let account: String = bech32::encode::<Bech32>(Hrp::parse(hrp)?, &base32_addr)?;
    Ok(account)
}


#[cfg(feature = "cosmwasm")]
pub fn pubkey_to_canonical(pubkey: &[u8]) -> cosmwasm_std::CanonicalAddr {
    cosmwasm_std::CanonicalAddr::from(
        cosmwasm_std::Binary(ripemd160(&sha256(pubkey)))
    )
}
