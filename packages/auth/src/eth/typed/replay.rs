use {
    saa_common::{ensure, to_json_binary as to_bin, wasm::Env, ReplayError},
    saa_crypto::{CheckOption, ReplayParams}
};
use crate::eth::EthTypedData;
use saa_crypto::hashes::keccak256;
use serde_json::Value;



#[allow(unused)]
fn hash_hex(bin: saa_common::Binary) -> String {
    hex::encode(keccak256(bin.as_slice()))
}


impl EthTypedData {

    fn msg_string(
        &self, 
        check: CheckOption
    ) -> String {
        match check {
            CheckOption::Messages(messages) => {
                match messages.len() {
                    0 => None,
                    1 => messages.first().cloned(),
                    _ => to_bin(&messages).map(hash_hex).ok()
                }
            },
            CheckOption::Text(t) => Some(t),
            CheckOption::Nothing => None
        }
        .or_else(|| {

        let key = self.message_property
            .as_deref()
            .unwrap_or("message");
        self.message
        .get(key)
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                v => saa_common::to_json_string(&v).ok()
            })
        .or_else(|| 
            self.message.gets(key)
            .and_then(|arr| {
                if arr.len() == 1 {
                    if let Some(f) = arr.first() {
                        return match f {
                            Value::String(s) => Some(s.clone()),
                            v => saa_common::to_json_string(&v).ok()
                        }
                    }
                }
                to_bin(&arr).map(hash_hex).ok()
            }
        ))})
        .or_else(|| {
            if !self.message.is_empty() {
                self.message.to_string().ok()
            } else {
                None
            }
        })
        .unwrap_or_default()
    }


}


impl saa_crypto::ReplayProtection for EthTypedData {

    fn hash_message(&self, bytes: &[u8]) -> Vec<u8> {
        keccak256(bytes).to_vec()
    }

    fn message_digest(&self) -> Vec<u8> {
        self.encode_eip712(None)
        .map(Into::into)
        .unwrap_or_default()
    }


    fn protect_reply(
        &self,
        env:  &Env,
        params: ReplayParams,
    ) -> Result<(), ReplayError> {
        let address = self.domain.verifying_contract.as_deref().unwrap_or_default();
        ensure!(address.starts_with("0x"), ReplayError::MissingData("verifying_contract".into()));

        let chain_id = match params.override_id {
            Some(ref id) => id.clone(),
            None => {
                #[cfg(not(feature = "cosmwasm"))]
                return Err(ReplayError::MissingData("Chain ID".into()));
                #[cfg(feature = "cosmwasm")]
                env.block.chain_id.clone()
            }
        };
        let addr = match params.override_address {
            Some(ref addr) => addr.clone(),
            None => {
                #[cfg(not(feature = "cosmwasm"))]
                return Err(ReplayError::MissingData("Contract Address".into()));
                #[cfg(feature = "cosmwasm")]
                env.contract.address.to_string()
            }
        };

        let msg_str = self.msg_string(params.checking.clone());
        
        // if both message and nonce are included in the signed message,
        // we only use chain_id and address to generate the verifying address
        // passed message property is ignored
        if self.message_property.is_some() {
            // println!("Message string nothing: {}", self.msg_string(CheckOption::Nothing));

            // message aren't included in the envelope.
            // however if passed we are making sure that they
            // are the same as the one in the signed message
            ensure!(msg_str == self.msg_string(CheckOption::Nothing), ReplayError::MessageMismatch(msg_str.clone()));

            if let Some(n) = self.message.nonce {
                ensure!(params.nonce == n.u64(), ReplayError::InvalidNonce(params.nonce));

                let addr_hash = self
                    .cache
                    .as_ref()
                    .and_then(|i| i.addr_hash.clone())
                    .unwrap_or(hex::encode(
                        &keccak256(&[chain_id.as_bytes(), addr.as_bytes()].concat())[12..]
                    ));

                ensure!(addr_hash == address[2..], ReplayError::AddressMismatch);
                return Ok(());
            }
        }


        // if the environment passed 'messages' as an argument
        // or the signed message field include a value(s) under
        // a given message property we inlude them and the nonce
        // in the replay attack hash
        let replay_hash = keccak256(&[
            chain_id.as_bytes(), 
            addr.as_bytes(),
            msg_str.as_bytes(), 
            &params.nonce.to_be_bytes()
        ].concat());

        let encoded = format!("0x{}", hex::encode(&replay_hash[12..]));

        ensure!(encoded == address, ReplayError::InvalidEnvelope(encoded, address.to_string()));
        Ok(())
    }

}

