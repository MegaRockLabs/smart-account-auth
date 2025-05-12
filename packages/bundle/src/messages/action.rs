use core::fmt::Display;
use saa_schema::wasm_serde;
use saa_common::{ensure, AuthError, FromStr, SessionError, ToString};
use strum::IntoDiscriminant;
#[cfg(feature = "wasm")]
use serde::Serialize;

use super::{is_session_action_name, SignedDataMsg};

#[wasm_serde]
pub enum DerivationMethod {
    Name,
    String,
    #[cfg(feature = "wasm")]
    Json
}

impl Default for DerivationMethod {
    fn default() -> Self {
        Self::Name
    }
}


#[wasm_serde]
pub struct  Action {
    pub result  :  String,
    pub method  :  DerivationMethod
}

impl Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.result)
    }
}


impl FromStr for Action {
    type Err = SessionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Action {
            result: s.to_string(),
            method: DerivationMethod::Name
        })
    }
}


impl Action {

    #[cfg(not(feature = "wasm"))]
    pub fn new<M : DerivableMsg>(message: &M, method: DerivationMethod) -> Result<Self, SessionError> {
        let name = message.discriminant().to_string();
        ensure!(!is_session_action_name(name.as_str()), SessionError::InnerSessionAction);
        let action = match method {
            DerivationMethod::Name => Self {
                method: DerivationMethod::Name,
                result: message.discriminant().to_string(),
            },
            DerivationMethod::String => Self {
                method: DerivationMethod::String,
                result: message.to_string(),
            },
        };
        ensure!(!action.result.is_empty(), SessionError::InvalidActions);
        Ok(action)
    }

    #[cfg(feature = "wasm")]
    pub fn new<M : DerivableMsg>(message: &M, method: DerivationMethod) -> Result<Self, SessionError> {
        let name = message.discriminant().to_string();
        ensure!(!is_session_action_name(name.as_str()), SessionError::InnerSessionAction);
        let action = match method {
            DerivationMethod::Name => Self {
                method: DerivationMethod::Name,
                result: message.discriminant().to_string(),
            },
            DerivationMethod::String => Self {
                method: DerivationMethod::String,
                result: message.to_string(),
            },
            DerivationMethod::Json => Self {
                method: DerivationMethod::Json,
                result: saa_common::wasm::to_json_string(message)
                    .map_err(|_| SessionError::DerivationError)?,
            },
        };
        ensure!(!action.result.is_empty(), SessionError::InvalidActions);
        Ok(action)
        
    }

    #[cfg(feature = "utils")]
    pub fn with_str<A : Display>(message: A) -> Self {
        Self {
            method: DerivationMethod::String,
            result: message.to_string()
        }
    }

    #[cfg(feature = "utils")]
    pub fn with_strum_name<A>(message: A) -> Self  
        where A: IntoDiscriminant<Discriminant : ToString>,
    {
        Self {
            method: DerivationMethod::Name,
            result: message.discriminant().to_string()
        }
    }

    #[cfg(all(feature = "wasm", feature = "utils"))]
    pub fn with_serde_name<A : Serialize>(message: A) -> Result<Self, SessionError> {
        Ok(Self {
            method: DerivationMethod::Name,
            result: serde_json::to_value(message)
                    .map_err(|_| SessionError::DerivationError)?
                    .as_object()
                    .map(|obj| obj.keys()
                        .next()
                        .map(|k| k.to_string())
                    )
                    .flatten()
                    .ok_or(SessionError::DerivationError)?
        })
    }

    #[cfg(all(feature = "wasm", feature = "utils"))]
    pub fn with_serde_json<A : Serialize>(message: A) -> Result<Self, SessionError> {
        Ok(Self {
            method: DerivationMethod::Json,
            result: saa_common::wasm::to_json_string(&message)
                    .map_err(|_| SessionError::DerivationError)?
        })
        
    }
}


#[wasm_serde]
pub enum ActionMsg<M> {
    Native(M),
    Signed(SignedDataMsg)
}




#[wasm_serde]
pub enum AllowedActions {
    Include(Vec<Action>),
    All {},
}



// a list e.g. Vec of Impl FromStr
impl<A : ToString> From<Vec<A>> for AllowedActions {
    fn from(actions: Vec<A>) -> Self {
        if actions.is_empty() {
            return AllowedActions::All {};
        } else {
            AllowedActions::Include(actions.into_iter()
                .map(|action| {
                    let result = action.to_string();
                    Action {
                        result,
                        method: DerivationMethod::Name
                    }
                })
                .collect())
        }
    }
}


impl AllowedActions {


    pub fn is_action_allowed(&self, act: &Action) -> bool {
        if match act.method {
            #[cfg(feature = "wasm")]
            DerivationMethod::Json => act.result.contains("\"session_actions\"") || 
                                        act.result.contains("\"session_info\""),
            _ => is_session_action_name(act.result.as_str())
        } {
            return false;
        }

        match self {
            AllowedActions::All {} => true,
            AllowedActions::Include(ref actions) => actions
                .iter()
                .any(|action| action == act)
        }
    }


    #[cfg(not(feature = "wasm"))]
    pub fn is_message_allowed<M : DerivableMsg>(&self, message: &M) -> bool {
        if self.is_msg_name_ok(message) {
            return false;
        }
        match self {
            AllowedActions::All {} => true,
            AllowedActions::Include(ref actions) => actions
                .iter()
                .any(|allowed| Action::new(
                        message, allowed.method
                    ).result == allowed.result
                )
        }
    }


    #[cfg(feature = "wasm")]
    pub fn is_message_allowed<M : DerivableMsg>(&self, message: &M) -> bool {
        if is_session_action_name(message.discriminant().as_ref()) {
            return false;
        }
        match self {
            AllowedActions::All {} => true,
            AllowedActions::Include(ref actions) => actions
                .iter()
                .any(|allowed| 
                    if let Ok(derived) = Action::new(message, allowed.method.clone()) {
                        allowed.result == derived.result
                    } else {
                        false
                    }
                )
        }
    }
}


#[cfg(feature = "utils")]
impl AllowedActions {


    pub fn is_name_allowed<M: AsRef<str>>(&self, msg: &M) -> bool 
        where M: strum::IntoDiscriminant<Discriminant : AsRef<str>>
    {
        if is_session_action_name(msg.discriminant().as_ref()) {
            return false;
        }
        match self {
            AllowedActions::All {} => true,
            AllowedActions::Include(ref actions) => actions
                .iter()
                .any(|action| 
                    action.method == DerivationMethod::Name && 
                    action.result.as_str() == msg.discriminant().as_ref()
                )
        }
    }


    pub fn is_str_allowed<S: ToString>(&self, msg: &S) -> bool {
        match self {
            AllowedActions::All {} => true,
            AllowedActions::Include(ref actions) => actions
                .iter()
                .any(|action| 
                    action.method == DerivationMethod::String && 
                    action.result == msg.to_string()
                )
        }
    }

    #[cfg(feature = "wasm")]
    pub fn is_json_allowed<M : Serialize>(&self, msg: &M) -> bool {
        match self {
            AllowedActions::All {} => true,
            AllowedActions::Include(ref actions) => actions
                .iter()
                .any(|action| {
                    if action.method != DerivationMethod::Json {
                        return false;
                    }
                    let res = Action::with_serde_json(msg)
                        .map(|msg| msg.result)
                        .unwrap_or_default();
                    action.result == res
                })
        }
      
    }

}




#[cfg(feature = "wasm")]
pub trait DerivableMsg 
    : Display + IntoDiscriminant  +  Clone  +  Serialize
    + IntoDiscriminant<Discriminant : ToString + AsRef<str>>
{
    fn name(&self) -> String;
    fn to_json_string(&self) -> Result<String, AuthError>;
}



#[cfg(not(feature = "wasm"))]
pub trait DerivableMsg 
    : Display + IntoDiscriminant + Clone
    + IntoDiscriminant<Discriminant : ToString + AsRef<str>>
{
    fn name(&self) -> String;
}



#[cfg(feature = "wasm")]
impl<M> DerivableMsg for M
where
    M : IntoDiscriminant + Display + Serialize + Clone,
    <M as IntoDiscriminant>::Discriminant : ToString + AsRef<str>,
{
    fn name(&self) -> String {
        self.discriminant().to_string()
    }

    // fn to_string() -> String
    
    fn to_json_string(&self) -> Result<String, AuthError> {
        saa_common::wasm::to_json_string(self)
            .map_err(|_| AuthError::generic("Failed to convert to JSON string"))
    }
}


/* impl<M : DerivableMsg> DerivableMsg for Box<M> {
    fn name(&self) -> String {
        (**self).name()
    }

    #[cfg(feature = "wasm")]
    fn to_json_string(&self) -> Result<String, AuthError> {
        (**self).to_json_string()
    }
}
 */


#[cfg(not(feature = "wasm"))]
impl<M> DerivableMsg for M
where
    M : IntoDiscriminant<Discriminant : ToString + AsRef<str>> + Display + Clone
{
    fn name(&self) -> String {
        self.discriminant().to_string()
    }
}
