use core::{fmt::Display, str::FromStr};
use saa_schema::{strum::IntoDiscriminant, wasm_serde};
use serde::Serialize;
use crate::AuthError;



#[wasm_serde]
// #[derive(strum_macros::Display)]
pub enum DerivationMethod {
    Name,
    String,
    #[cfg(feature = "wasm")]
    Json
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
    type Err = AuthError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Action {
            result: s.to_string(),
            method: DerivationMethod::Name
        })
    }
}



impl Action {

    pub fn with_str<A : Display>(action: A) -> Self {
        Self {
            method: DerivationMethod::String,
            result: action.to_string()
        }
    }

    pub fn with_strum_name<A>(action: A) -> Self  where A: IntoDiscriminant<Discriminant : ToString>{
        Self {
            method: DerivationMethod::Name,
            result: action.discriminant().to_string()
        }
    }

    #[cfg(feature = "wasm")]
    pub fn with_serde_name<A : Serialize>(action: A) -> Result<Self, AuthError> {
        Ok(Self {
            method: DerivationMethod::Name,
            result: serde_json::to_value(action)
                    .map_err(|_| AuthError::generic("Failed to serialize action"))?
                    .as_object()
                    .map(|obj| obj.keys()
                        .next()
                        .map(|k| k.to_string())
                    )
                    .flatten()
                    .ok_or(AuthError::generic("Failed to serialize action"))?
        })
    }

    #[cfg(feature = "wasm")]
    pub fn with_serde_json<A : Serialize>(action: A) -> Result<Self, AuthError> {
        Ok(Self {
            method: DerivationMethod::Json,
            result: serde_json_wasm::to_string(&action)
                    .map_err(|_| AuthError::generic("Failed to serialize action"))?
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
                .any(|action| action.result == msg.result)
        }
    }


    pub fn is_str_allowed<S: ToString>(&self, msg: &S) -> bool {
        match self {
            AllowedActions::All {} => true,
            AllowedActions::List(ref actions) => actions
                .iter()
                .any(|action| action.result == msg.to_string())
        }
    }

    #[cfg(feature = "wasm")]
    pub fn is_json_allowed<M : Serialize>(&self, msg: &M) -> bool {

        match self {
            AllowedActions::All {} => true,
            AllowedActions::List(ref actions) => actions
                .iter()
                .any(|action| {
                    let res = if let DerivationMethod::Name = action.method {
                        Action::with_serde_name(msg) 
                    } else {
                        Action::with_serde_json(msg)
                    };
                    match res {
                        Ok(res) => action.result == res.result,
                        Err(_) => false
                    }
                })
        }
      
    }

}
