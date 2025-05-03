use core::{fmt::Display, str::FromStr};
use saa_schema::{strum::IntoDiscriminant, strum_macros, wasm_serde};
use serde::Serialize;

use crate::AuthError;


pub struct DefaultMarker;
struct SerdeMarker;
struct DispayMarker;



pub trait ActionId<Marker = DefaultMarker> {
    fn derive_name(&self) -> String {
        String::default()
    }
    fn derive_string(&self) -> String where Self: Display {
        self.to_string()
    }
    fn derive_json(&self) -> String where Self: Serialize {
        serde_json_wasm::to_string(self).unwrap_or_default()
    }
}


impl <S> ActionId for S where
    S: IntoDiscriminant<Discriminant : ToString>,
{
    fn derive_name(&self) -> String {
        self.discriminant().to_string()
    }
}


impl<S : Serialize> ActionId<String> for S {

    fn derive_name(&self) -> String {
        serde_json::to_value(self)
            .ok()
            .map(|val| val.as_object().cloned())
            .flatten()
            .map(|obj| obj.keys()
                .next()
                .map(|k| k.to_string())
            )
            .flatten()
            .unwrap_or_default()     
    }
}




pub trait ActionName<Marker = DefaultMarker> {
    fn name(&self) -> String;
}


impl<S> ActionName for S where
    S: IntoDiscriminant<Discriminant : ToString>,
{
    fn name(&self) -> String {
        self.discriminant().to_string()
    }
}

impl<S : Display> ActionName<DispayMarker> for S {
    fn name(&self) -> String {
        return self.to_string();        
    }
}


#[cfg(feature = "wasm")]
impl<S : Serialize> ActionName<SerdeMarker> for S {
    fn name(&self) -> String {
        serde_json::to_value(self)
            .ok()
            .map(|val| val.as_object().cloned())
            .flatten()
            .map(|obj| obj.keys()
                .next()
                .map(|k| k.to_string())
            )
            .flatten()
            .unwrap_or_default()     
    }
}



#[wasm_serde]
#[derive(strum_macros::Display)]
pub enum Derivation {
    Name,
    String,
    #[cfg(feature = "wasm")]
    Json
}




#[wasm_serde]
pub struct  ActionDerivation<M: ActionName + Display + Serialize> {
    pub message :  M,
    pub method  :  Derivation
}

impl<A : ActionName + Display +  Serialize> Display for ActionDerivation<A> 
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.method {
            Derivation::Name => write!(f, "{}", self.message.name()),
            Derivation::String => write!(f, "{}", self.message.to_string()),
            #[cfg(feature = "wasm")]
            Derivation::Json => write!(f, "{}", serde_json_wasm::to_string(&self.message).unwrap_or_default())
        }
    }
}



#[wasm_serde]
pub enum Action<A : ActionName + Display + Serialize> {
    Named(String),
    Derived(ActionDerivation<A>)
}



impl<A : ActionName + Display + Serialize> Display for Action<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Named(name) => write!(f, "{}", name),
            Action::Derived(der) => write!(f, "{}", der.to_string())
        }
    }
}


impl<A : ActionName + Display + Serialize> FromStr for Action<A> {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Action::Named(s.to_string()))
    }
}



#[wasm_serde]
pub enum AllowedActions<A : ActionName + Display + Serialize> {
    Current(Action<A>),
    List(Vec<Action<A>>),
    All {},
}



impl<A : ActionName + Display + Serialize> Action<A>{

    pub fn is_allowed<O : ToString>(&self, msg: &O) -> bool {
        match self {
            Action::Named(name) => *name == msg.to_string(),
            Action::Derived(der) => msg.to_string() == der.to_string()
        }
    }

}


impl<A : ActionName + Display + Serialize> AllowedActions<A> {

    pub fn is_allowed<O : ToString>(&self, msg: &O) -> bool {
        match self {
            AllowedActions::All {} => true,
            AllowedActions::Current(a) => a.is_allowed(msg),
            AllowedActions::List(ref actions) => actions.iter()
                .any(|action| action.is_allowed(msg)),
        }
    }

}



