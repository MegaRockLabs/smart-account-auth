use saa_common::hashes::{ripemd160, sha256};
use bech32::{ToBase32, Variant};

pub fn pubkey_to_account(pubkey: &[u8], hrp: &str) -> String {
    let base32_addr = ripemd160(&sha256(pubkey)).to_base32();
    let account: String = bech32::encode(hrp, base32_addr, Variant::Bech32).unwrap();
    account
}

#[cfg(feature = "cosmwasm")]
pub fn pubkey_to_canonical(pubkey: &[u8]) -> cosmwasm_std::CanonicalAddr {
    cosmwasm_std::CanonicalAddr(cosmwasm_std::Binary(ripemd160(&sha256(pubkey))))
}


pub fn preamble_msg_arb_036(signer: &str, data: &str) -> String {
    format!(
        "{{\"account_number\":\"0\",\"chain_id\":\"\",\"fee\":{{\"amount\":[],\"gas\":\"0\"}},\"memo\":\"\",\"msgs\":[{{\"type\":\"sign/MsgSignData\",\"value\":{{\"data\":\"{}\",\"signer\":\"{}\"}}}}],\"sequence\":\"0\"}}", 
        data, signer
    )
}

