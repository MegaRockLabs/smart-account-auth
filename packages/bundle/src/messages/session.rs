
use std::fmt::Display;
use saa_schema::wasm_serde;
use saa_common::{CredentialId, Expiration, FromStr};
use strum::{IntoDiscriminant, IntoEnumIterator};
use strum_macros::{AsRefStr, Display, EnumIter, EnumString};

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
}


#[wasm_serde]
pub struct CreateSession {
    pub allowed_actions     :      AllowedActions,
    pub session_info        :      SessionInfo,
}



#[cfg(feature = "wasm")]
#[wasm_serde]
pub struct CreateSessionFromMsg<M>
where
    M: core::ops::Deref,
    M::Target: strum::IntoDiscriminant + core::fmt::Display + serde::Serialize + Clone,
    <M::Target as strum::IntoDiscriminant>::Discriminant: AsRef<str>,
{
    pub message             :      M,
    pub derivation_method   :      Option<DerivationMethod>,
    pub session_info        :      SessionInfo,
}



#[derive(AsRefStr, EnumString, EnumIter, PartialEq, Display)]
#[strum(serialize_all = "snake_case")]
pub enum SessionActionName {
    CreateSession,
    #[cfg(feature = "wasm")]
    CreateSessionFromMsg,
}




impl Display for CreateSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "create_session")
    }
}

impl AsRef<str> for CreateSession {
    fn as_ref(&self) -> &str {
        "create_session"
    }
}   



impl IntoDiscriminant for CreateSession {
    type Discriminant = SessionActionName;

    fn discriminant(&self) -> Self::Discriminant {
        SessionActionName::CreateSession
    }
}




#[cfg(feature = "wasm")]
impl<M> Display for CreateSessionFromMsg<M>
where
    M: core::ops::Deref,
    M::Target: strum::IntoDiscriminant + core::fmt::Display + serde::Serialize + Clone,
    <M::Target as strum::IntoDiscriminant>::Discriminant: AsRef<str>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "create_session_from_msg")
    }
    
}

#[cfg(feature = "wasm")]
impl<M> AsRef<str> for CreateSessionFromMsg<M>
where
    M: core::ops::Deref,
    M::Target: strum::IntoDiscriminant + core::fmt::Display + serde::Serialize + Clone,
    <M::Target as strum::IntoDiscriminant>::Discriminant: AsRef<str>,
{
    fn as_ref(&self) -> &str {
        "create_session_from_msg"
    }
}



#[cfg(feature = "wasm")]
impl<M> IntoDiscriminant for CreateSessionFromMsg<M>
where
    M: core::ops::Deref,
    M::Target: strum::IntoDiscriminant + core::fmt::Display + serde::Serialize + Clone,
    <M::Target as strum::IntoDiscriminant>::Discriminant: AsRef<str>,
{
    type Discriminant = SessionActionName;

    fn discriminant(&self) -> Self::Discriminant {
        SessionActionName::CreateSessionFromMsg
    }
}



pub(crate) fn is_session_action_name(name: &str) -> bool {
    SessionActionName::iter()
        .any(|action| {
            if action.as_ref() == name {
                return true;
            }
            if let Ok(act) = SessionActionName::from_str(name) {
                return action == act;
            }
            false
        })
}