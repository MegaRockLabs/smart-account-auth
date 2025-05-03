use core::fmt::Display;
use saa_schema::wasm_serde;
use serde::Serialize;

use crate::{types::expiration::Expiration, CredentialId};
use super::action::{ActionName, AllowedActions};


#[wasm_serde]
pub enum Authority {
    Address(String),
    Credential(CredentialId),
}



#[wasm_serde]
pub struct SessionKey<A : ActionName + Display + Serialize> {
    pub granter     : Authority,
    pub grantee     : Authority,
    pub actions     : AllowedActions<A>, 
    pub expiration  : Expiration
}

