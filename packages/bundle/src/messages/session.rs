
use core::fmt::Display;
use saa_schema::wasm_serde;
use saa_common::{to_json_binary, Binary, CredentialId, Expiration, FromStr, Timepoint};
use strum::{IntoDiscriminant, IntoEnumIterator};
use strum_macros::{AsRefStr, Display, EnumIter, EnumString};

use crate::{utils, CredentialInfo};
use super::{AllowedActions, DerivationMethod, SignedDataMsg};

pub type GranteeInfo = (CredentialId, CredentialInfo);


#[wasm_serde]
pub struct Session {
    pub granter     : Option<CredentialId>,
    pub grantee     : GranteeInfo,
    pub actions     : AllowedActions, 
    pub expiration  : Expiration,
    pub created_at  : Timepoint,
    pub nonce       : u64,
}



impl Session {
    pub fn key(&self) -> CredentialId {
        // hash together the granter, grantee, and actions
        let (id, info) = &self.grantee;
        let granter = self.granter.clone().unwrap_or_default();
        let actions = to_json_binary(&self.actions).unwrap_or_default();

        let msg = [
            granter.as_bytes(),
            id.as_bytes(),
            info.name.to_string().as_bytes(),
            actions.as_slice(),
        ].concat();

        Binary::new(utils::hashes::sha256(&msg)).to_base64()
    }
    
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


#[wasm_serde]
pub enum MessageOption<M> {
    Native(M),
    Signed(SignedDataMsg)
}



#[wasm_serde]
pub struct WithSessionMsg<M> {
    pub message             :      MessageOption<M>,
    pub session_key         :      String,
}


#[wasm_serde]
pub struct RevokeKeyMsg {
    pub session_key         :      String,
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