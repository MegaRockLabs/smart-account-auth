use crate::eth::EthTypedData;
use saa_common::{ensure, ToString};
use serde_json::Value;

#[cfg(feature = "cosmwasm")]
use {
    saa_common::{ReplayError, wasm::Env, to_json_binary as to_bin},
    saa_crypto::hashes::keccak256,
};



/* impl EthTypedData {

    fn msg_nonce(&self) -> Option<[u8; 8]> {
        self.message.get("nonce")
        .or(self.message.get("Nonce"))
        .and_then(|v| 
            v.as_u64()
                .map(|n| n.to_be_bytes())
            .or_else(|| 
                v.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .map(|n| n.to_be_bytes())
            )
        )
    }

}
 */

#[cfg(feature = "cosmwasm")]
fn hash_hex(bin: saa_common::Binary) -> String {
    hex::encode(keccak256(bin.as_slice()))
}


#[cfg(feature = "cosmwasm")]
impl EthTypedData {

    fn msg_string<M: serde::Serialize + core::fmt::Display>(
        &self, 
        messages: &Option<Vec<M>>
    ) -> String {
        messages
            .as_ref()
            .and_then(|msgs|{
                match msgs.len() {
                    0 => None,
                    1 => msgs.first().and_then(|msg| {
                        let str = msg.to_string();
                        println!("Arg string: {}", str);
                        let jb = format!("\"{}\"", str).as_bytes().to_vec();
                        to_bin(&msg).ok()
                        .map(|b| if b == jb { str } else { hash_hex(b) })
                    }),
                    _ => to_bin(&msgs).map(hash_hex).ok()
                }
            })
            .or_else(|| {
                let key = self.message_property
                    .as_deref()
                    .unwrap_or("message");
                self.message
                .get(key)
                    .and_then(|v| match v {
                        Value::String(s) => Some(s.clone()),
                        _ => to_bin(v).map(hash_hex).ok()
                    })
                    .or_else(|| 
                        self.message.get(&format!("{}s", key))
                        .and_then(|v| to_bin(v).map(hash_hex).ok()
                    ))
            })
            .unwrap_or_default()
    }

}


impl saa_crypto::ReplayProtection for EthTypedData {

    fn hash_message(&self, bytes: &[u8]) -> Vec<u8> {
        keccak256(bytes).to_vec()
    }

    fn message_digest(&self) -> Vec<u8> {
        self.encode_eip712()
        .map(Into::into)
        .unwrap_or_default()
    }

    #[cfg(feature = "cosmwasm")]
    fn check_replay<M: serde::Serialize + core::fmt::Display>(
        &self,
        env:  &Env,
        messages: &Option<Vec<M>>,
        nonce: u64,
    ) -> Result<(), ReplayError> {
        use crate::eth::utils::encode_u64;
        let chain_id = encode_u64(self.domain.chain_id.unwrap_or_default().u64());
        ensure!(chain_id == [0; 32], ReplayError::ChainIdMismatch);

        let address = self.domain.verifying_contract.as_deref().unwrap_or_default();
        ensure!(address.starts_with("0x"), ReplayError::MissingData("verifying_contract".into()));

        println!("Msg string: {}", self.msg_string(messages));

        let replay_hash = keccak256(
            &[
                env.block.chain_id.as_bytes(),
                env.contract.address.as_bytes(),
                self.msg_string(messages).as_bytes(),
                &nonce.to_be_bytes(),
            ]
            .concat()
        );


        ensure!(hex::encode(&replay_hash[12..]) == &address[2..], ReplayError::InvalidEnvelope);
        println!("Expected address: 0x{}", address);
        Ok(())
    }

}

