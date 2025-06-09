use saa_schema::saa_type;
use serde::Serialize;
use crate::PayloadExtension;


/// Payload message used for telling which credential to use
/// or how to modify it
#[saa_type]
pub struct AuthPayload {
    /// Which credential to use if multiple are available
    pub credential_id   :   Option<crate::CredentialId>,
    /// Human readable prefix to use to derive an address
    pub hrp             :   Option<String>,
    /// Additional arguments to pass depending on a credential in question
    pub extension       :   Option<PayloadExtension>,
}



/// A wrapper for signed data used for constructing credentials and verifying them
/// `data` is base64 encoded JSON string that contains the data to be verified.  
/// When `replay` feature tag is enabled, must be a JSON object corresponding to `MsgDataToSign` struct.
#[saa_type]
pub struct SignedDataMsg {
    /// Base64 encoded JSON string of replay envelope, serialized actions messages, both of them or none of them
    pub data        :   crate::Binary,
    /// Signature to verify the data
    pub signature   :   crate::Binary,
    /// Optional payload to use customize the verification flow if possible
    pub payload     :   Option<AuthPayload>,
}


#[saa_type]
pub struct MsgDataToSign<M: Serialize = String> {
    pub chain_id: String,
    pub contract_address: String,
    pub messages: Vec<M>,
    pub nonce: crate::Uint64,
}




#[saa_type(no_deny)]
pub struct MsgDataToVerify {
    pub chain_id: String,
    pub contract_address: String,
    pub nonce: crate::Uint64,
}



impl<M : Serialize> Into<MsgDataToVerify> for &MsgDataToSign<M> {
    fn into(self) -> MsgDataToVerify {
        MsgDataToVerify {
            chain_id: self.chain_id.clone(),
            contract_address: self.contract_address.clone(),
            nonce: self.nonce.clone(),
        }
    }
}




#[cfg(feature = "wasm")]
mod wasm {

    impl<M : serde::Serialize> super::MsgDataToSign<M> {
        pub fn new_binary(
            env: &crate::wasm::Env,
            nonce: crate::Uint64,
            messages: Vec<M>
        ) -> Result<crate::Binary, crate::ReplayError> {
            crate::to_json_binary(&Self{
                chain_id: env.block.chain_id.clone(),
                contract_address: env.contract.address.to_string(),
                messages,
                nonce,
            }).map_err(|_| crate::ReplayError::ToBin("MsgDataToSign".to_string()))
        }
    }

    impl crate::wasm::CustomMsg for super::SignedDataMsg {}
}