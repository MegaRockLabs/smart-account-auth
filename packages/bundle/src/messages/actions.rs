use core::fmt::Display;
use saa_schema::wasm_serde;
use saa_common::{AuthError, ToString};
use super::SignedDataMsg;


#[wasm_serde]
#[derive(Default)]
pub enum DerivationMethod {
    #[default]
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





#[cfg(feature = "wasm")]
pub trait DerivableMsg 
    : Display + Clone + serde::Serialize + strum::IntoDiscriminant
    + strum::IntoDiscriminant<Discriminant : ToString + AsRef<str>>
{
    fn name(&self) -> String;
    fn to_json_string(&self) -> Result<String, AuthError>;
}



#[cfg(not(feature = "wasm"))]
pub trait DerivableMsg 
    : Display + Clone + strum::IntoDiscriminant
    + strum::IntoDiscriminant<Discriminant : ToString + AsRef<str>>
{
    fn name(&self) -> String;
}

