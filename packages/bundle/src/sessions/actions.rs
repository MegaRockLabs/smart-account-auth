
use saa_schema::wasm_serde;
use strum::IntoDiscriminant;
use strum_macros::{AsRefStr, Display, EnumIter, EnumString};

use crate::{SessionInfo, messages::actions::DerivableMsg};
use crate::msgs::{ActionMsg, AllowedActions, DerivationMethod};



#[wasm_serde]
pub struct CreateSession {
    pub allowed_actions     :      AllowedActions,
    pub session_info        :      SessionInfo,
}


#[wasm_serde]
pub struct CreateSessionFromMsg<M : DerivableMsg> {
    pub message             :      M,
    pub derivation          :      Option<DerivationMethod>,
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




pub trait SessionActionsMatch : DerivableMsg  {
    fn match_actions(&self) -> Option<SessionActionMsg<Self>>;
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

