use saa_common::{format, hashes::{ripemd160, sha256}, AuthError, String};
use bech32::{hrp::Hrp, Bech32};

pub fn pubkey_to_account(pubkey: &[u8], hrp: &str) -> Result<String, AuthError> {
    let base32_addr = ripemd160(&sha256(pubkey));
    let account: String = bech32::encode::<Bech32>(Hrp::parse(hrp)?, &base32_addr).unwrap();
    Ok(account)
}

#[cfg(feature = "cosmwasm")]
pub fn pubkey_to_canonical(pubkey: &[u8]) -> cosmwasm_std::CanonicalAddr {
    cosmwasm_std::CanonicalAddr::from(
        cosmwasm_std::Binary(
            ripemd160(&sha256(pubkey))
        )
    )
}


pub fn preamble_msg_arb_036(signer: &str, data: &str) -> String {
    format!(
        "{{\"account_number\":\"0\",\"chain_id\":\"\",\"fee\":{{\"amount\":[],\"gas\":\"0\"}},\"memo\":\"\",\"msgs\":[{{\"type\":\"sign/MsgSignData\",\"value\":{{\"data\":\"{}\",\"signer\":\"{}\"}}}}],\"sequence\":\"0\"}}", 
        data, signer
    )
}

