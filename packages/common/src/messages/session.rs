use core::{fmt::Display, str::FromStr};

use saa_schema::wasm_serde;
use serde::Serialize;

use crate::{types::expiration::Expiration, AuthError, CredentialId};

#[wasm_serde]
pub struct MsgGrant {
    pub granter: String,
    pub grantee: String,
    pub nonce: String,
}


pub trait ActionName {
    fn name(&self) -> Result<String, AuthError>;
}


impl<S: Serialize> ActionName for S {

    fn name(&self) -> Result<String, AuthError> {
        match serde_json::to_value(self) {
            Ok(value) => {
                println!("Name Value: {:?}", value);
                value.as_object()
                    .ok_or_else(|| AuthError::generic("Not an object".to_string()))?
                    .keys()
                    .next()
                    .map(|k| k.to_string())
                    .ok_or_else(|| AuthError::generic("No name found".to_string()))
            },
            Err(e) => {
                println!("Error serializing to JSON: {:?}", e);
                Err(AuthError::generic(e.to_string()))   
            }
        }
    }
}



#[wasm_serde]
pub enum ActionDerivation {
    Name,
    String,
    Json
}


impl ActionDerivation {
    pub fn derive_message<M: Serialize + Display + ActionName>(&self, action: &M) -> String {
        match self {
            ActionDerivation::Name => action.name().unwrap_or_default(),
            ActionDerivation::String => action.to_string(),
            ActionDerivation::Json => serde_json_wasm::to_string(action).unwrap_or_default()
        }
    }
    
}



#[wasm_serde]
pub struct  ActionToDerive<A: Serialize + Display + ActionName> {
    pub action:  A,
    pub method:  ActionDerivation
}


impl <A: Serialize + Display + ActionName> ActionToDerive<A> {
    pub fn derive(&self) -> String {
        match self.method {
            ActionDerivation::Name => self.action.name().unwrap_or_default(),
            ActionDerivation::String => self.action.to_string(),
            ActionDerivation::Json => serde_json_wasm::to_string(&self.action).unwrap_or_default()
        }
    }
    
}



#[wasm_serde]
pub enum Action<M : Serialize + Display + ActionName> {
    Named(String),
    Derived(ActionToDerive<M>)
}

impl<M> FromStr for Action <M> 
where
    M: Serialize + Display + ActionName,
{
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Action::Named(s.to_string()))
    }
}

impl<M> ToString for Action <M> 
where
    M: Serialize + Display + ActionName,
{   fn to_string(&self) -> String {
        match self {
            Action::Named(name) => name.clone(),
            Action::Derived(derived) => derived.derive()
        }
    }
}



#[wasm_serde]
pub enum AllowedActions<M : Serialize + Display + ActionName> {
    Current(ActionDerivation),
    List(Vec<Action<M>>),
    All {},
}



#[wasm_serde]
pub enum Authority {
    Address(String),
    Credential(CredentialId),
}



#[wasm_serde]
pub struct SessionKey<M : Serialize + Display + ActionName = String> {
    pub granter     : Authority,
    pub grantee     : Authority,
    pub actions     : AllowedActions<M>, 
    pub expiration  : Expiration
}

