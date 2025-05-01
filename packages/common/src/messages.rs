
use core::fmt::Debug;
use saa_schema::wasm_serde;

use crate::{ensure, AuthError, Binary};


#[wasm_serde]
pub struct AuthPayload<E = Binary> {
    pub hrp: Option<String>,
    pub address: Option<String>,
    pub credential_id: Option<Binary>,
    pub extension: Option<E>
}


impl<E> AuthPayload<E> {

    pub fn validate(&self) -> Result<(), AuthError> {
        let error : &str = "Only one of the 'address' or 'hrp' can be provided";

        if self.hrp.is_some() {
            ensure!(
                self.address.is_none(),
                AuthError::generic(error)
            );
        }
        if self.address.is_some() {
            ensure!(self.hrp.is_none(), AuthError::generic(error));
            let addr = self.address.clone().unwrap();
            ensure!(
                addr.len() > 3 && (addr.starts_with("0x") || addr.contains("1")),
                AuthError::generic("Invalid address")
            );
        }
        Ok(())
    }

    
}


#[wasm_serde]
pub struct MsgDataToSign<M = String> {
    pub chain_id: String,
    pub contract_address: String,
    pub messages: Vec<M>,
    pub nonce: String,
}


#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "wasm", derive(
    ::saa_schema::serde::Serialize,
    ::saa_schema::serde::Deserialize,
    ::saa_schema::schemars::JsonSchema
), schemars(crate = "::saa_schema::schemars"
))]
#[cfg_attr(feature = "substrate", derive(
    ::saa_schema::scale::Encode, ::saa_schema::scale::Decode
))]
#[cfg_attr(feature = "solana", derive(
    ::saa_schema::borsh::BorshSerialize, ::saa_schema::borsh::BorshDeserialize
))]
#[cfg_attr(all(feature = "std", feature="substrate"), derive(::saa_schema::scale_info::TypeInfo))]
#[allow(clippy::derive_partial_eq_without_eq)]
pub struct MsgDataToVerify {
    pub chain_id: String,
    pub contract_address: String,
    pub nonce: String,
}


impl<M> Into<MsgDataToVerify> for &MsgDataToSign<M> {
    fn into(self) -> MsgDataToVerify {
        MsgDataToVerify {
            chain_id: self.chain_id.clone(),
            contract_address: self.contract_address.clone(),
            nonce: self.nonce.clone(),
        }
    }
}



#[wasm_serde]
pub struct SignedDataMsg {
    pub data: Binary,
    pub signature: Binary,
    pub payload: Option<AuthPayload>,
}
