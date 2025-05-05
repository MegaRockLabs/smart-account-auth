use saa_schema::wasm_serde;


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

