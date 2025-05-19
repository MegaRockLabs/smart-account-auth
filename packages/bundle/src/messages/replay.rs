use saa_common::Uint64;
use saa_schema::saa_type;


#[saa_type]
pub struct MsgDataToSign<M = String> {
    pub chain_id: String,
    pub contract_address: String,
    pub messages: Vec<M>,
    pub nonce: Uint64,
}



#[saa_type(no_deny)]
pub struct MsgDataToVerify {
    pub chain_id: String,
    pub contract_address: String,
    pub nonce: Uint64,
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

