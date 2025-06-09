use saa_common::{format, String};

pub fn wrap_msg_arb_036(signer: &str, data: &str) -> String {
    format!(
        "{{\"account_number\":\"0\",\"chain_id\":\"\",\"fee\":{{\"amount\":[],\"gas\":\"0\"}},\"memo\":\"\",\"msgs\":[{{\"type\":\"sign/MsgSignData\",\"value\":{{\"data\":\"{}\",\"signer\":\"{}\"}}}}],\"sequence\":\"0\"}}", 
        data, signer
    )
}

pub fn prefix_from_address(address: &str) -> String {
    address.split("1").next().unwrap().to_string()
}

#[cfg(not(feature = "cosmos_arb_cache"))]
pub use saa_crypto::{pubkey_to_address, pubkey_to_canonical};