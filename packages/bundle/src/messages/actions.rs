use core::fmt::Display;
use saa_schema::saa_type;
use saa_common::ToString;


#[saa_type]
#[derive(Default)]
pub enum ActionDerivation {
    #[default]
    Name,
    String,
    #[cfg(feature = "wasm")]
    Json
}


#[saa_type]
#[derive(Default)]
pub enum AllQueryDerivation {
    #[default]
    Names,
    Strings,
}



#[saa_type]
pub struct  Action {
    pub result  :  String,
    pub method  :  ActionDerivation
}




#[saa_type]
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
    fn to_json_string(&self) -> Result<String, saa_common::AuthError>;
}



#[cfg(not(feature = "wasm"))]
pub trait DerivableMsg 
    : Display + Clone + strum::IntoDiscriminant
    + strum::IntoDiscriminant<Discriminant : ToString + AsRef<str>>
{
    fn name(&self) -> String;
}

