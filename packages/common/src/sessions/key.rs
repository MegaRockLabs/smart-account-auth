use saa_schema::wasm_serde;

use crate::{types::expiration::Expiration, CredentialId};
use super::action::AllowedActions;



#[wasm_serde]
pub struct SessionKey {
    pub granter     : Option<CredentialId>,
    pub grantee     : CredentialId,
    pub actions     : AllowedActions, 
    pub expiration  : Expiration
}

