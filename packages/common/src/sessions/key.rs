use saa_schema::wasm_serde;

use crate::{types::expiration::Expiration, CredentialId};
use super::action::AllowedActions;


#[wasm_serde]
pub enum Authority {
    Address(String),
    Credential(CredentialId),
}



#[wasm_serde]
pub struct SessionKey {
    pub granter     : Authority,
    pub grantee     : Authority,
    pub actions     : AllowedActions, 
    pub expiration  : Expiration
}

