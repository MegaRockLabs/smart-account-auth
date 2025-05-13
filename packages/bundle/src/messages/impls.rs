use core::fmt::Display;
use strum::IntoDiscriminant;
use saa_common::{AuthError, SessionError, FromStr, ToString, ensure};
use super::actions::{Action, AllowedActions, DerivationMethod, DerivableMsg};
use super::utils::is_session_action_name;



impl Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.result)
    }
}


impl FromStr for Action {
    type Err = AuthError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Action {
            result: s.to_string(),
            method: DerivationMethod::Name
        })
    }
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





#[cfg(feature = "wasm")]
impl<M> DerivableMsg for M
where
    M : IntoDiscriminant + Display + serde::Serialize + Clone,
    <M as IntoDiscriminant>::Discriminant : ToString + AsRef<str>,
{
    fn name(&self) -> String {
        self.discriminant().to_string()
    }

    fn to_json_string(&self) -> Result<String, AuthError> {
        saa_common::to_json_string(self)
            .map_err(|_| AuthError::generic("Failed to convert to JSON string"))
    }
}



#[cfg(not(feature = "wasm"))]
impl<M> DerivableMsg for M
where
    M : IntoDiscriminant<Discriminant : ToString + AsRef<str>> + Display + Clone
{
    fn name(&self) -> String {
        self.discriminant().to_string()
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
                result: saa_common::to_json_string(message)
                    .map_err(|_| SessionError::DerivationError)?,
            },
        };
        ensure!(!action.result.is_empty(), SessionError::InvalidActions);
        Ok(action)
        
    }

    #[cfg(feature = "utils")]
    pub fn with_str<A : core::fmt::Display>(message: A) -> Self {
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
    pub fn with_serde_name<A : serde::Serialize>(message: A) -> Result<Self, SessionError> {
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
    pub fn with_serde_json<A : serde::Serialize>(message: A) -> Result<Self, SessionError> {
        Ok(Self {
            method: DerivationMethod::Json,
            result: saa_common::to_json_string(&message)
                    .map_err(|_| SessionError::DerivationError)?
        })
        
    }
}



impl AllowedActions {


    pub fn can_do_action(&self, act: &Action) -> bool {
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
    pub fn can_do_msg<M : DerivableMsg>(&self, message: &M) -> bool {
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
    pub fn can_do_msg<M : DerivableMsg>(&self, message: &M) -> bool {
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


    pub fn can_do_name<M: AsRef<str>>(&self, msg: &M) -> bool 
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


    pub fn can_do_str<S: saa_common::ToString>(&self, msg: &S) -> bool {
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
    pub fn can_do_json<M : serde::Serialize>(&self, msg: &M) -> bool {
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


