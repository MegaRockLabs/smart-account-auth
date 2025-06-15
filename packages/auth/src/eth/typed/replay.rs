use crate::eth::EthTypedData;
#[cfg(feature = "cosmwasm")]
use saa_crypto::{CheckOption, ReplayParams};
use serde_json::Value;

#[cfg(feature = "cosmwasm")]
use {
    saa_common::{ensure, ReplayError, wasm::Env, to_json_binary as to_bin},
    saa_crypto::hashes::keccak256,
};



impl EthTypedData {
    pub(crate) fn msg_nonce(&self) -> Option<u64> {
        self.message.get("nonce")
        .or(self.message.get("Nonce"))
        .and_then(|v| v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        )
    }
}


#[allow(unused)]
fn hash_hex(bin: saa_common::Binary) -> String {
    hex::encode(keccak256(bin.as_slice()))
}


#[cfg(feature = "cosmwasm")]
impl EthTypedData {

    #[cfg(not(feature = "optimise"))]
    fn msg_string<M: serde::Serialize + core::fmt::Display>(
        &self, 
        check: CheckOption<M>
    ) -> String {

        let str = match check {
            CheckOption::Messages(messages) => {
                match messages.len() {
                    0 => String::new(),
                    1 => messages.first()
                    .map_or_else(
                    || String::new(),
                    |msg| {
                        let str = msg.to_string();
                        let jb = format!("\"{}\"", str).as_bytes().to_vec();
                        to_bin(&msg).ok()
                        .map(|b| if b == jb { str } else { hash_hex(b) })
                        .unwrap_or_default()
                    }),
                    _ => to_bin(&messages).map(hash_hex).unwrap_or_default()
                }
            },
            CheckOption::Text(t) => t,
            CheckOption::Nothing => String::new(),
        };

        if str.is_empty() {
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
                    .and_then(|v| match v {
                        Value::Array(arr) => {
                            if arr.len() == 1 {
                                if let Some(Value::String(s)) = arr.first() {
                                    return Some(s.clone())
                                }
                            }
                            to_bin(arr).map(hash_hex).ok()
                        },
                        _ => None
                    }
                ))
                .unwrap_or_default()
        } else {
            str
        }

    
    }

    #[cfg(feature = "optimise")]
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
                v => Some(v.to_string())
            })
        .or_else(|| 
            self.message.get(&format!("{}s", key))
            .and_then(|v| match v {
                Value::Array(arr) => {
                    if arr.len() == 1 {
                        if let Some(f) = arr.first() {
                            return match f {
                                Value::String(s) => Some(s.clone()),
                                v => Some(v.to_string())
                            }
                        }
                    }
                    let bin = to_bin(arr);
                    println!("Array to bin: {:?}", bin);
                    let hash = keccak256(&bin.unwrap());
                    println!("Array hash: {:?}", hash);
                    println!("Array hash hex: {:?}", hex::encode(&hash));
                    to_bin(arr).map(hash_hex).ok()
                },
                _ => None
            }
        ))})
        .or_else(|| {
            use saa_common::to_json_string;
            println!("Message is empty, trying to convert to JSON string");

            if self.message.is_empty() {
                return None;
            }

            println!("\n\nmessage to json string: {}\n\n", to_json_string(&self.message).unwrap());
            println!("message to value sting: {}\n\n", serde_json::to_value(&self.message).unwrap().to_string());
            println!("message to serde sting: {}\n\n", serde_json::to_string(&self.message).unwrap());
            println!("message from iter string: {}\n\n\n", Value::from_iter(self.message.iter().map(|(k, v)| (k.clone(), v.clone()))).to_string());
            
            saa_common::to_json_string(&self.message).ok()
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

    #[cfg(all(feature = "cosmwasm", not(feature = "optimise")))]
    fn protect_reply<M: serde::Serialize + core::fmt::Display + Clone>(
        &self,
        env:  &Env,
        params: ReplayParams<M>,
    ) -> Result<(), ReplayError> {
        let address = self.domain.verifying_contract.as_deref().unwrap_or_default();
        ensure!(address.starts_with("0x"), ReplayError::MissingData("verifying_contract".into()));

        let id_bytes = env.block.chain_id.as_bytes();
        let addr_bytes = env.contract.address.as_bytes();
        let msg_str = self.msg_string(params.checking.clone());

        // if both message and nonce are included in the signed message,
        // we only use chain_id and address to generate the verifying address
        // passed message property is ignored
        if self.message_property.is_some() {

            // message aren't included in the envelope.
            // however if passed we are making sure that they
            // are the same as the one in the signed message
            /* if params.has_inners {
            } */
            ensure!(msg_str == self.msg_string::<M>(CheckOption::Nothing), ReplayError::InvalidEnvelope);

            if let Some(n) = self.msg_nonce() {
                ensure!(params.nonce == n, ReplayError::InvalidNonce(params.nonce));

                let addr_hash = self
                    .cache
                    .as_ref()
                    .and_then(|i| i.addr_hash.clone())
                    .unwrap_or(hex::encode(
                        &keccak256(&[id_bytes, addr_bytes].concat())[12..]
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
            id_bytes, 
            addr_bytes, 
            msg_str.as_bytes(), 
            &params.nonce.to_be_bytes()
        ].concat());

        ensure!(hex::encode(&replay_hash[12..]) == address[2..], ReplayError::InvalidEnvelope);
        Ok(())
    }



    #[cfg(all(feature = "cosmwasm", feature = "optimise"))]
    fn protect_reply(
        &self,
        env:  &Env,
        params: ReplayParams,
    ) -> Result<(), ReplayError> {
        let address = self.domain.verifying_contract.as_deref().unwrap_or_default();
        ensure!(address.starts_with("0x"), ReplayError::MissingData("verifying_contract".into()));

        let id_bytes = env.block.chain_id.as_bytes();
        let addr_bytes = env.contract.address.as_bytes();
        let msg_str = self.msg_string(params.checking.clone());
        
      /*   
        println!("Replay attack check string: {}", msg_str);
        println!("Msg hash hex: {}", hex::encode(keccak256(msg_str.as_bytes())));
        println!("Given Address: {}", address); */

     
        // if both message and nonce are included in the signed message,
        // we only use chain_id and address to generate the verifying address
        // passed message property is ignored
        if self.message_property.is_some() {
            // println!("Message string nothing: {}", self.msg_string(CheckOption::Nothing));

            // message aren't included in the envelope.
            // however if passed we are making sure that they
            // are the same as the one in the signed message
            ensure!(msg_str == self.msg_string(CheckOption::Nothing), ReplayError::InvalidEnvelope);


            if let Some(n) = self.msg_nonce() {
                ensure!(params.nonce == n, ReplayError::InvalidNonce(params.nonce));

                let addr_hash = self
                    .cache
                    .as_ref()
                    .and_then(|i| i.addr_hash.clone())
                    .unwrap_or(hex::encode(
                        &keccak256(&[id_bytes, addr_bytes].concat())[12..]
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
            id_bytes, 
            addr_bytes, 
            msg_str.as_bytes(), 
            &params.nonce.to_be_bytes()
        ].concat());

        
        if self.primary_type == "Prompt"
        {
            println!("\n\nReplay attack check string: {}\n", msg_str);
            println!("Msg bytes: {:?}", msg_str.as_bytes());
            println!("Message hash hex: {}", hex::encode(&keccak256(msg_str.as_bytes())));
            println!("Params nonce: {:?}", params);
            println!("ID bytes: {:?}", id_bytes);
            println!("Address bytes: {:?}", addr_bytes);
            println!("Params nonce bytes: {:?}", params.nonce.to_be_bytes());
            println!("Replay attack chain id: {}", env.block.chain_id);
            println!("Replay attack address: {}", env.contract.address);
            println!("Replay attack nonce {:?}", params.nonce);
            println!("Replay hash: {}", hex::encode(replay_hash));
            println!("Generated address: 0x{}", hex::encode(&replay_hash[12..]));
            println!("Given Address: {}\n\n", address);
        }


        ensure!(hex::encode(&replay_hash[12..]) == address[2..], ReplayError::InvalidEnvelope);
        Ok(())
    }

}

