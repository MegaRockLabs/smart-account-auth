mod impls;
use saa_schema::wasm_serde;
use saa_common::{CredentialId, Expiration};
use crate::{credential::CredentialRecord, msgs::AllowedActions};
pub mod actions;


type GranteeInfo = CredentialRecord;


#[wasm_serde]
pub struct SessionInfo  {
    pub grantee     :       GranteeInfo,
    pub granter     :       Option<CredentialId>,
    pub expiration  :       Option<Expiration>,
}



#[wasm_serde]
pub struct Session {
    pub granter     : CredentialId,
    pub grantee     : GranteeInfo,
    pub actions     : AllowedActions, 
    pub expiration  : Expiration,
    #[cfg(feature = "replay")]
    pub nonce       : u64,
}







/* 

#[wasm_serde]

pub enum SessionQueryMsg<M : DerivableMsg> {
    AllActions {}
}



pub trait SessionQueriesMatch : DerivableMsg  {
    fn match_queries(&self) -> Option<SessionActionMsg<Self>>;
}

*/
