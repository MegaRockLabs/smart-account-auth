
use saa_schema::wasm_serde;
use saa_common::{to_json_binary, Binary, CredentialId, Expiration, FromStr};
use strum::{IntoDiscriminant, IntoEnumIterator};
use strum_macros::{AsRefStr, Display, EnumIter, EnumString};

use crate::CredentialInfo;
use super::{ActionMsg, AllowedActions, DerivableMsg, DerivationMethod};


pub type GranteeInfo = (CredentialId, CredentialInfo);


#[wasm_serde]
pub struct Session {
    pub granter     : CredentialId,
    pub grantee     : GranteeInfo,
    pub actions     : AllowedActions, 
    pub expiration  : Expiration,
    pub nonce       : u64,
}



impl Session {
    pub fn key(&self) -> CredentialId {
        let (id, info) = &self.grantee;
        let actions = to_json_binary(&self.actions).unwrap_or_default();

        let msg = [
            self.granter.as_bytes(),
            id.as_bytes(),
            info.name.to_string().as_bytes(),
            actions.as_slice(),
        ].concat();

        Binary::from(saa_common::hashes::sha256(&msg)).to_base64()
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
pub struct CreateSessionFromMsg<M : DerivableMsg> {
    pub message             :      M,
    pub derivation_method   :      Option<DerivationMethod>,
    pub session_info        :      SessionInfo,
}




#[wasm_serde]
pub struct WithSessionMsg<M> {
    pub message             :      ActionMsg<M>,
    pub session_key         :      String,
}


#[wasm_serde]
pub struct RevokeKeyMsg {
    pub session_key         :      String,
}




#[wasm_serde]
pub enum SessionActionMsg<M : DerivableMsg> {
    CreateSession(CreateSession),
    CreateSessionFromMsg(CreateSessionFromMsg<M>),
    WithSessionKey(WithSessionMsg<M>),
    RevokeSession(RevokeKeyMsg),
}




#[derive(AsRefStr, EnumString, EnumIter, PartialEq, Display)]
#[strum(serialize_all = "snake_case")]
pub enum SessionActionName {
    SessionActions,
    CreateSession,
    CreateSessionFromMsg,
    WithSessionKey,
    RevokeSession,
}


impl<M : DerivableMsg> IntoDiscriminant for SessionActionMsg<M> {
    type Discriminant = SessionActionName;
    fn discriminant(&self) -> Self::Discriminant {
        match self {
            SessionActionMsg::CreateSession(_) => SessionActionName::CreateSession,
            SessionActionMsg::CreateSessionFromMsg(_) => SessionActionName::CreateSessionFromMsg,
            SessionActionMsg::WithSessionKey(_) => SessionActionName::WithSessionKey,
            SessionActionMsg::RevokeSession(_) => SessionActionName::RevokeSession,
        }
    }
    
}



impl core::fmt::Display for CreateSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "create_session")
    }
}

impl AsRef<str> for CreateSession {
    fn as_ref(&self) -> &str {
        "create_session"
    }
}   


impl<M : DerivableMsg> core::fmt::Display for CreateSessionFromMsg<M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "create_session_from_msg")
    }
    
}
impl<M : DerivableMsg> AsRef<str> for CreateSessionFromMsg<M> {
    fn as_ref(&self) -> &str {
        "create_session_from_msg"
    }
}



impl IntoDiscriminant for CreateSession {
    type Discriminant = SessionActionName;
    fn discriminant(&self) -> Self::Discriminant {
        SessionActionName::CreateSession
    }
}
impl<M : DerivableMsg> IntoDiscriminant for CreateSessionFromMsg<M> {
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




pub trait SessionActionsMatch : DerivableMsg  {
    fn match_actions(&self) -> Option<SessionActionMsg<Self>>;
}