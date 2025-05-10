use saa_schema::wasm_serde;
use saa_common::{Expiration, CredentialId};

use crate::CredentialInfo;
use super::{AllowedActions, DerivationMethod};

pub type GranteeInfo = (CredentialId, CredentialInfo);


#[wasm_serde]
pub struct SessionKey {
    pub granter     : Option<CredentialId>,
    pub grantee     : GranteeInfo,
    pub actions     : AllowedActions, 
    pub expiration  : Expiration
}



#[wasm_serde]
pub struct SessionInfo  {
    pub grantee     :       GranteeInfo,
    pub granter     :       Option<CredentialId>,
    pub expiration  :       Option<Expiration>,
    pub actions     :       Option<AllowedActions>,
}


#[wasm_serde]
pub struct CreateSession {
    pub allowed_actions     :      AllowedActions,
    pub session_info        :      SessionInfo,
}



#[cfg(feature = "wasm")]
#[wasm_serde]
pub struct CreateSessionForMsg<M>
where
    M: core::ops::Deref,
    M::Target: strum::IntoDiscriminant + core::fmt::Display + serde::Serialize + Clone,
    <M::Target as strum::IntoDiscriminant>::Discriminant: ToString,
{
    pub message             :      M,
    pub derivation_method   :      Option<DerivationMethod>,
    pub session_info        :      SessionInfo,
}

