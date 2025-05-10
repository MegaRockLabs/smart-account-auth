use core::{fmt::Display, str::FromStr};
use saa_schema::wasm_serde;
use saa_common::SessionError;
use strum::IntoDiscriminant;
#[cfg(feature = "wasm")]
use serde::Serialize;

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
    pub fn new<M>(message: M, method: DerivationMethod) -> Self
    where
        M:  IntoDiscriminant<Discriminant : ToString> + Display,
    {
        match method {
            DerivationMethod::Name => Self {
                method: DerivationMethod::Name,
                result: message.discriminant().to_string(),
            },
            DerivationMethod::String => Self {
                method: DerivationMethod::String,
                result: message.to_string(),
            },
            // Json not supported without wasm feature
        }
    }

    #[cfg(feature = "wasm")]
    pub fn new<M>(message: M, method: DerivationMethod) -> Result<Self, SessionError>
    where
        M:  IntoDiscriminant<Discriminant : ToString> + Display + Serialize,
    {
        match method {
            DerivationMethod::Name => Ok(Self {
                method: DerivationMethod::Name,
                result: message.discriminant().to_string(),
            }),
            DerivationMethod::String => Ok(Self {
                method: DerivationMethod::String,
                result: message.to_string(),
            }),
            DerivationMethod::Json => Ok(Self {
                method: DerivationMethod::Json,
                result: saa_common::wasm::to_json_string(&message)
                    .map_err(|_| SessionError::DerivationError)?,
            }),
        }
    }

    #[cfg(feature = "utils")]
    pub fn with_str<A : Display>(action: A) -> Self {
        Self {
            method: DerivationMethod::String,
            result: action.to_string()
        }
    }

    #[cfg(feature = "utils")]
    pub fn with_strum_name<A>(action: A) -> Self  where A: IntoDiscriminant<Discriminant : ToString>{
        Self {
            method: DerivationMethod::Name,
            result: action.discriminant().to_string()
        }
    }

    #[cfg(all(feature = "wasm", feature = "utils", test))]
    pub fn with_serde_name<A : Serialize>(action: A) -> Result<Self, SessionError> {
        Ok(Self {
            method: DerivationMethod::Name,
            result: serde_json::to_value(action)
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
    pub fn with_serde_json<A : Serialize>(action: A) -> Result<Self, SessionError> {
        Ok(Self {
            method: DerivationMethod::Json,
            result: saa_common::wasm::to_json_string(&action)
                    .map_err(|_| SessionError::DerivationError)?
        })
        
    }
}




#[wasm_serde]
pub enum AllowedActions {
    List(Vec<Action>),
    All {},
}



// a list e.g. Vec of Impl FromStr
impl<A : ToString> From<Vec<A>> for AllowedActions {
    fn from(actions: Vec<A>) -> Self {
        if actions.is_empty() {
            return AllowedActions::All {};
        } else {
            AllowedActions::List(actions.into_iter()
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
    pub fn is_action_allowed(&self, msg: &Action) -> bool {
        match self {
            AllowedActions::All {} => true,
            AllowedActions::List(ref actions) => actions
                .iter()
                .any(|action| 
                    action.method == msg.method && 
                    action.result == msg.result
                )
        }
    }
}


#[cfg(feature = "utils")]
impl AllowedActions {


    pub fn is_name_allowed<M: ToString>(&self, msg: &M) -> bool 
        where M: strum::IntoDiscriminant<Discriminant : ToString>
    {
        match self {
            AllowedActions::All {} => true,
            AllowedActions::List(ref actions) => actions
                .iter()
                .any(|action| 
                    action.method == DerivationMethod::Name && 
                    action.result == msg.discriminant().to_string()
                )
        }
    }


    pub fn is_str_allowed<S: ToString>(&self, msg: &S) -> bool {
        match self {
            AllowedActions::All {} => true,
            AllowedActions::List(ref actions) => actions
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
            AllowedActions::List(ref actions) => actions
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
