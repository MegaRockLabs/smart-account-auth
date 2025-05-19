use std::{fmt::Debug, str::FromStr};
use serde::{Deserialize, Serialize};
use strum::{EnumCount, EnumMessage, IntoDiscriminant, IntoEnumIterator, 
    VariantMetadata, VariantNames, VariantArray, 
};
use strum_macros::{EnumString, Display, FromRepr, EnumDiscriminants, EnumIter};
use crate::types::CosmosMsg;


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Normal {
    CamelStruct { param1: String, param2: u32 },
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
enum Tag {
    CamelStruct { param1: String, param2: u32 },
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WithType {
    Struct { r#type: String },
    Type {  },
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WithEmptyType {
    Type,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WithEnumType {
    Type(String),
    EnumType(String),
}



#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
enum TagWithEnumType {
    CamelStruct { param1: String, param2: u32 },
    Type(String)
}



#[derive(Debug, Clone, Serialize, Deserialize, EnumString, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Strum {
    CamelStruct {},

    #[strum(serialize = "another_struct", serialize = "another")]
    AnotherStruct {},

    #[strum(serialize = "yet")]
    YetAnotherStruct {},
}

impl Default for Strum {
    fn default() -> Self {
        Strum::CamelStruct {}
    }
}


#[derive(Debug, Clone, Serialize, Deserialize, EnumString)]
#[strum(serialize_all = "snake_case")]
enum StrumOnlySnake {
    CamelStruct {},
    #[strum(serialize = "AnotherStruct")]
    AnotherStruct {},
}


#[derive(Debug, Clone, Serialize, Deserialize, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
enum StrumSnake {
    CamelStruct {},

    #[strum(serialize = "AnotherStruct")]
    AnotherStruct {},
}


#[derive(Debug, Clone, Serialize, Deserialize, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
enum StrumComplex {
    Action(String),
    Execute { msgs: Vec<CosmosMsg> },
    Strum { strum: Strum },
    Struct { param1: String, param2: u32, param3: Vec<StrumSnake> }
}



#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
enum Actions {
    #[strum(
        to_string = "{{\"one\":{{\"param1\":\"{param1}\",\"param2\":{param2}}}}}",
        serialize = "one",
    )]
    One { param1: String, param2: u32 },
    Two { },
    #[strum(
        to_string = "{{\"three\":{{\"msg\":\"{msg}\"}}}}",
        serialize = "three",
    )]
    Three { msg: String },
    #[strum(to_string = "four_{0}", serialize = "four")]
    Four(String)
}

impl Default for Actions {
    fn default() -> Self {
        Actions::Two {}
    }
    
}



#[derive(Debug, Clone, Serialize, Deserialize, EnumString, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
enum StrumDisplay {
    CamelStruct {},

    #[strum(to_string = "simple: {0}", serialize = "simple")]
    SimpleAction(String),

    #[strum(to_string = "{0}", serialize = "action")]
    Action(Actions),

    #[strum(
        to_string = "{{\"action\":\"{action}\",\"payload\":\"{payload}\",\"type\":\"{another_type}\"}}",
        serialize = "another",
    )]
    AnotherStruct { action: Actions, payload: String, another_type: String },

    #[strum(
        to_string = "{{\"action\":{action},\"payload\":\"{payload}\",\"type\":\"{another_type}\"}}",
        serialize = "json",
    )]
    AnotherJsonStruct { action: Actions, payload: String, another_type: String },
}



#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Traited {
    Unit,
    Action {},
    CamelStruct { param1: String, param2: u32 },
    AnotherStruct(String),
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag="type")]
enum TagTraited {
    Unit,
    Action {},
    CamelStruct { param1: String, param2: u32 },
    AnotherStruct(String),
}



#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, 
    Display, strum_macros::VariantNames, strum_macros::EnumString
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
enum StrumTraited {
    #[default]
    Unit,

    Action { },

    CamelStruct { param1: String, param2: u32 },

    #[strum(to_string = "another_{0}", serialize = "another_struct")]
    AnotherStruct(String),
}



#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, 
    Display, EnumString, FromRepr, EnumDiscriminants, EnumIter, 
    strum_macros::VariantNames, strum_macros::EnumCount, strum_macros::EnumMessage
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(strum(serialize_all = "snake_case"))]
#[strum_discriminants(derive(EnumString, Display, EnumIter, 
    strum_macros::EnumMessage, strum_macros::VariantArray)
)]
enum MegaStrumTraited {
    #[default]
    Unit,
    Action { },
    CamelStruct { param1: String, param2: u32 },
    #[strum(
        to_string = "another_{0}", 
        serialize = "another_struct",
        message = "Another Message",
        detailed_message = "Detailed Anotherness",
    )]
    AnotherStruct(String),
}


impl VariantMetadata for MegaStrumTraited {
    const VARIANT_COUNT: usize = Self::COUNT;
    const VARIANT_NAMES: &'static [&'static str] = &Self::VARIANTS;
    fn variant_name(&self) -> &'static str {
        match self {
            MegaStrumTraited::Unit => "unit",
            MegaStrumTraited::Action { .. } => "action",
            MegaStrumTraited::CamelStruct { .. } => "camel_struct",
            MegaStrumTraited::AnotherStruct(_) => "another_struct",
        }
    }
}




#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, 
    Display, EnumString,
)]
#[serde(rename_all = "snake_case", tag="type")]
#[strum(serialize_all = "snake_case")]
enum MultiTraited {
    Action {},
    CamelStruct { action: Actions, payload: String },
    #[strum(
        to_string = "{{\"action\":\"{action}\",\"payload\":\"{payload}\"}}", 
        serialize = "another",
    )]
    AnotherStruct { action: Actions, payload: String },
}

impl Default for MultiTraited {
    fn default() -> Self {
        MultiTraited::Action {}
    }
    
}

impl VariantNames for MultiTraited {
    const VARIANTS: &'static [&'static str] = &["action", "camel_struct", "another_struct"];
}

impl VariantMetadata for MultiTraited {
    const VARIANT_COUNT: usize = 3;
    const VARIANT_NAMES: &'static [&'static str] = &["action", "camel_struct", "another_struct"];
    fn variant_name(&self) -> &'static str {
        match self {
            MultiTraited::Action { .. } => "action",
            MultiTraited::CamelStruct { .. } => "camel_struct",
            MultiTraited::AnotherStruct { .. } => "another_struct",
            // MultiTraited::AnotherStruct { .. } => self.to_string().leak()
        }
    }
}



trait SimpleNameTrait  {
    fn simple_name(&self) -> String;
}

impl SimpleNameTrait for Traited {
    fn simple_name(&self) -> String {
        match self {
            Traited::CamelStruct { .. } => "camel_struct".to_string(),
            Traited::AnotherStruct(_) => "another_struct".to_string(),
            Traited::Action { .. } => "action".to_string(),
            Traited::Unit => "unit".to_string(),
        }
    }
}

impl SimpleNameTrait for TagTraited {
    fn simple_name(&self) -> String {
        match self {
            TagTraited::CamelStruct { .. } => "camel_struct".to_string(),
            TagTraited::AnotherStruct(_) => "another_struct".to_string(),
            TagTraited::Action { .. } => "action".to_string(),
            TagTraited::Unit => "unit".to_string(),
        }
    }
}

impl SimpleNameTrait for StrumTraited {
    fn simple_name(&self) -> String {
        match self {
            StrumTraited::CamelStruct { .. } => "camel_struct".to_string(),
            StrumTraited::AnotherStruct(_) => "another_".to_string(),
            StrumTraited::Action { .. } => "action".to_string(),
            StrumTraited::Unit => "unit".to_string(),
        }
    }
}

impl<M: VariantMetadata> SimpleNameTrait for M {
    fn simple_name(&self) -> String {
        self.variant_name().to_string()
    }
}



trait SerdeTagTrait {
    fn serde_name(&self) -> Option<String>;
}

impl<T: Serialize> SerdeTagTrait for T {
    fn serde_name(&self) -> Option<String> {
        get_type(self)
    }
}


trait StrumTrait {
    fn strum_name(&self) -> Option<String>;
}


impl<T: ToString + FromStr + PartialEq + VariantNames> StrumTrait for T {
    fn strum_name(&self) -> Option<String> {
        let vars: &[&str] = T::VARIANTS;
        let str = self.to_string();
        let str_copy = Self::from_str(&str).ok();

        let found = vars.iter()
            .any(|&v| {
                if v.to_string() == self.to_string() {
                    return true;
                }
                let var_copy = Self::from_str(v).ok();
                if str_copy == var_copy {
                    return true;
                }
                if let Some(var) = var_copy {
                    var.to_string() == str
                } else {
                    false
                }
            });

        if found {
            Some(str)
        } else {
            None
        }
        
    }
}



fn has_property<T: Serialize>(
    action: &T,
    key: &str,
) -> bool {
    let val = serde_json::to_value(action);
    match val {
        Ok(serde_json::Value::Object(map)) => map.contains_key(key),
        _ => false,
    }
}

fn assert_property<A: Serialize + Clone + Debug>(
    action: &A,
    key: &str,
    assert_str: Option<&str>,
)  {
    let val = serde_json::to_value(action.clone()).ok();
    if let None = val {
        assert!(false, "Failed to serialize action: {:?}", action);
    }
    let val = val.unwrap();
    let name = val.get(key);
    
    if let Some(name) = name {
        if let Some(name) = name.as_str() {
            if let Some(assert_name) = assert_str {
                assert_eq!(name, assert_name, "Expected name: {}, but got: {}", assert_name, name);
            }
        } else {
            assert!(assert_str.is_none(), "Expected a string to assert but got {:?}", name);
        }
    } else {
        assert!(assert_str.is_none(), "Expected a string to assert, but got {:?}", name);
    }
}



fn assert_type<A: Serialize + Clone + Debug>(
    action: &A,
    assert_str: Option<&str>,
)  {
    assert_property(action, "type", assert_str);
}


fn get_type<T: Serialize>(msg: &T) -> Option<String> {
    serde_json::to_value(msg)
        .ok()?
        .get("type")?
        .as_str()
        .map(|s| s.to_owned())
}



#[test]
fn test_tag_types() {
    
    // normal behavior is that we can check if it's a specific variant by checking 
    // if it has a property however we can't extract a property name from the enum
    let action = Normal::CamelStruct { param1: "simple".to_string(), param2: 1 };
    assert!(has_property(&action, "camel_struct"));
    assert!(!has_property(&action, "type"));

    
    /* ------------------------------------------- */

    // serde that automatically adds a tag  that tells the name of the current variant
    let action = Tag::CamelStruct { param1: "tagged".to_string(), param2: 2 };
    let prop : &str = "camel_struct";
    assert!(!has_property(&action, prop));
    assert!(has_property(&action, "param1"));
    assert!(has_property(&action, "type"));

    let action_type = get_type(&action);
    assert_eq!(action_type, Some(prop.to_string()));
    assert_property(&action, prop, None);
    assert_type(&action, action_type.as_deref());

    /* ------------------------------------------- */

    // adding a confusing Type variant to a struct that isn't marked with a serdr tag
    // property exists but it doesn't mean the same thing
    let action = WithType::Type { };
    assert!(has_property(&action, "type"));
    assert!(!has_property(&action, "struct"));
    assert!(get_type(&action).is_none());
    assert_type(&action, None);

    // other variants are not affected
    let action = WithType::Struct { r#type: "my_type".to_string() };
    assert!(has_property(&action, "struct"));
    assert!(!has_property(&action, "type"));
    assert!(get_type(&action).is_none());
    
    // can't really serialize so not even possible to check for inclusion
    let action = WithEmptyType::Type;
    assert!(!has_property(&action, "type"));
    assert_type(&action, None);

    // this would full the serde tag base serializer
    let action = WithEnumType::Type("my_type".to_string());
    assert!(has_property(&action, "type"));
    assert_eq!(get_type(&action), Some("my_type".to_string()));
    assert_type(&action, Some("my_type"));

    // however this is not the case
    let action = WithEnumType::EnumType("my_type".to_string());
    assert!(has_property(&action, "enum_type"));
    assert!(!has_property(&action, "type"));
    assert_eq!(get_type(&action), None);
    assert_type(&action,None);
    assert_property(&action, "enum_type", Some("my_type")); 

    /* ------------------------------------------- */

    // tag completely changes the behavior so we get the confusing moments like this
    let action = TagWithEnumType::Type("my_tag_type".to_string());
    assert!(!has_property(&action, "type"));
    assert_eq!(get_type(&action), None);


}



#[test]
fn test_scrum_types() {

    let action = Strum::from_str("camel_struct");
    assert!(action.is_err());

    let action = Strum::from_str("CamelStruct").unwrap();
    assert!(has_property(&action, "camel_struct"));
    assert!(!has_property(&action, "CamelStruct"));
    assert!(!has_property(&action, "another_struct"));


    let action = Strum::from_str("AnotherStruct");
    assert!(action.is_err());

    let action = Strum::from_str("another_struct").unwrap();
    assert!(has_property(&action, "another_struct"));
    assert!(!has_property(&action, "AnotherStruct"));


    let action = Strum::from_str("another").unwrap();
    assert!(has_property(&action, "another_struct"));
    assert!(!has_property(&action, "another"));

    
    assert!(Strum::from_str("yet_another_struct").is_err());
    assert!(Strum::from_str("YetAnotherStruct").is_err());
    assert!(Strum::from_str("yet").is_ok());

    /* ------------------------------------------- */

    let action = StrumOnlySnake::from_str("camel_struct").unwrap();
    assert!(!has_property(&action, "camel_struct"));
    assert!(has_property(&action, "CamelStruct"));

    assert!(StrumOnlySnake::from_str("CamelStruct").is_err());
    assert!(StrumOnlySnake::from_str("another_struct").is_err());

    let action = StrumOnlySnake::from_str("AnotherStruct").unwrap();
    assert!(!has_property(&action, "another_struct"));
    assert!(has_property(&action, "AnotherStruct"));

    /* ------------------------------------------- */
    
    assert!(StrumSnake::from_str("another_struct").is_err());
    assert!(StrumSnake::from_str("CamelStruct").is_err());

    let action = StrumSnake::from_str("camel_struct").unwrap();
    assert!(has_property(&action, "camel_struct"));
    assert!(!has_property(&action, "CamelStruct"));


    let action = StrumSnake::from_str("AnotherStruct").unwrap();
    assert!(has_property(&action, "another_struct"));
    assert!(!has_property(&action, "AnotherStruct"));
    

    /* ------------------------------------------- */

    assert!(StrumComplex::from_str("action").is_ok());

    let action = StrumComplex::from_str("execute").unwrap();
    assert!(has_property(&action, "execute"));
    assert!(!has_property(&action, "msgs"));


    let action = StrumComplex::from_str("struct").unwrap();
    assert!(has_property(&action, "struct"));
    assert!(!has_property(&action, "param1"));

    
    let simple_strum = Strum::from_str("CamelStruct").unwrap();
    let action = StrumComplex::from_str("strum").unwrap();
    assert!(has_property(&action, "strum"));

    if let StrumComplex::Strum { strum } = action {
        assert!(has_property(&strum, "camel_struct"));
        assert_eq!(strum, simple_strum);
    } else {
        panic!("Expected Strum variant");
    }


    /* ------------------------------------------- */

    let name = "camel_struct";
    assert_eq!(StrumDisplay::CamelStruct{}.to_string(), name);
    assert_eq!(StrumDisplay::from_str(name).unwrap().to_string(), name);

    assert_eq!(StrumDisplay::from_str("simple").unwrap().to_string(), "simple: ");
    assert_eq!(StrumDisplay::SimpleAction("Text here".to_string()).to_string(), "simple: Text here");


    let strum = StrumDisplay::from_str("action").unwrap();
    assert_eq!(strum.to_string(), "two");
    assert_eq!(strum.to_string(), Actions::from_str("two").unwrap().to_string());
    assert_eq!(strum.to_string(), Actions::default().to_string());


    let another = StrumDisplay::from_str("another").unwrap();
    assert_eq!(another.to_string(), "{\"action\":\"two\",\"payload\":\"\",\"type\":\"\"}");

    let another = StrumDisplay::AnotherStruct { 
        action: Actions::One { param1: String::from("uno"), param2: 47 },
        another_type: "ano".to_string(),
        payload: "imp".to_string() 
    };
    
    assert_eq!(
        another.to_string(), 
        "{\"action\":\"{\"one\":{\"param1\":\"uno\",\"param2\":47}}\",\"payload\":\"imp\",\"type\":\"ano\"}"
    );

    //  serde_json_wasm::from_str(another.to_string().as_str()).unwrap();

}



#[test]
fn test_trait_types() {

    // SimpleNameTrait 
    let action = Traited::Action {  };
    assert!(has_property(&action, "action"));
    assert!(!has_property(&action, "simple_name"));

    let name = action.simple_name();
    assert_eq!(name, "action".to_string());

    let another = Traited::AnotherStruct(String::default());
    assert!(has_property(&another, "another_struct"));
    assert!(!has_property(&another, "another_one")); // DeeeJaaay Khaled
    assert_eq!(another.simple_name(), "another_struct".to_string());
    
    /* ------------------------------------------- */

    // SerdeTagTrait
    let camel = Tag::CamelStruct { param1: "tag trait".to_string(), param2: 99 };
    assert!(has_property(&camel, "param1"));
    assert!(has_property(&camel, "type"));
    assert_eq!(camel.serde_name(), Some("camel_struct".to_string()));

    assert_eq!(action.serde_name(), None);
    assert_eq!(another.serde_name(), None);


    /* ------------------------------------------- */

    // TagTraited
    let camel = TagTraited::CamelStruct { param1: "tag trait".to_string(), param2: 99 };
    assert!(has_property(&camel, "param1"));
    assert!(has_property(&camel, "type"));

    assert_eq!(camel.serde_name(), Some("camel_struct".to_string()));
    assert_eq!(camel.simple_name(), "camel_struct".to_string());

    let action : TagTraited = serde_json::from_str("{\"type\":\"action\"}").unwrap();
    assert_eq!(action.serde_name(), Some(action.simple_name()));


    /* ------------------------------------------- */

    // StrumTrait
    let camel = StrumTraited::CamelStruct { param1: "strum".to_string(), param2: 0 };
    assert_eq!(camel.strum_name(), Some("camel_struct".to_string()));
    
    assert_eq!(StrumTraited::Action{}.strum_name(), Some("action".to_string()));
    assert_eq!(StrumTraited::Unit.strum_name(), Some("unit".to_string()));
    assert_eq!(StrumTraited::default().strum_name(), Some("unit".to_string()));

    // default works
    assert_eq!(StrumTraited::AnotherStruct("".into()).strum_name(), Some("another_".to_string()));
    // "struct" works  
    assert_eq!(StrumTraited::AnotherStruct("struct".into()).strum_name(), Some("another_struct".to_string()));
    // anything else doesn't work
    assert_eq!(StrumTraited::AnotherStruct("another".into()).strum_name(), None);

}


#[test]
fn test_mega_strum() {
    let names = MegaStrumTraited::VARIANT_NAMES;
    assert_eq!(names, MegaStrumTraited::VARIANTS);
    assert_eq!(names, &["unit", "action", "camel_struct", "another_{0}"]);
    
    let count = MegaStrumTraited::VARIANT_COUNT;
    assert_eq!(count, MegaStrumTraited::COUNT);
    assert_eq!(count, names.len());
    assert_eq!(count, 4);

    let discriminants = MegaStrumTraitedDiscriminants::VARIANTS;
    assert_eq!(discriminants, &[
        MegaStrumTraitedDiscriminants::Unit, 
        MegaStrumTraitedDiscriminants::Action, 
        MegaStrumTraitedDiscriminants::CamelStruct, 
        MegaStrumTraitedDiscriminants::AnotherStruct
    ]);

    let mut iter = MegaStrumTraited::iter();
    let first = iter.next().unwrap();
    assert_eq!(first, MegaStrumTraited::Unit);
    assert_eq!(first.to_string(), "unit".to_string());

    let disc = first.discriminant();
    assert_eq!(first.to_string(), disc.to_string());
    assert_eq!(first, MegaStrumTraited::from_str(&disc.to_string()).unwrap());
    assert_eq!(MegaStrumTraitedDiscriminants::from_str(&first.to_string()).unwrap(), disc);


    let action = MegaStrumTraited::from_repr(1).unwrap();
    assert_eq!(action, MegaStrumTraited::Action{ });
    assert_eq!(action, MegaStrumTraited::from_str("action").unwrap());
    assert_eq!(action.to_string(), "action".to_string());


    let camel = MegaStrumTraited::CamelStruct { param1: "mega".to_string(), param2: 0 };
    let name = "camel_struct";
    assert_eq!(camel.variant_name(), name);
    assert_eq!(camel.simple_name(), name.to_string());
    assert_eq!(camel.strum_name(), Some(name.to_string()));
    assert_eq!(camel.serde_name(), None);

    assert!(has_property(&camel, "camel_struct"));
    assert!(!has_property(&camel, "type"));
    assert!(!has_property(&camel, "param1"));
    assert!(!has_property(&camel, "variant_name"));
    assert!(!has_property(&camel, "simple_name"));
    assert!(!has_property(&camel, "strum_name"));
    assert!(!has_property(&camel, "serde_name"));


    let inner = "day here we go again";
    let another = MegaStrumTraited::AnotherStruct(inner.to_string());
    assert_eq!(another.to_string(), format!("another_{}", inner));
    assert_eq!(another.variant_name(), "another_struct");
    assert_eq!(another.get_message().unwrap(), "Another Message");
    assert_eq!(another.get_detailed_message().unwrap(), "Detailed Anotherness");
}



#[test]
fn test_complex_transform() {

    let multi = MultiTraited::AnotherStruct { 
        action: Actions::Two {}, 
        payload: String::from("pay") 
    };

    let name = "another_struct";
    assert_eq!(multi.variant_name(), name);
    assert_eq!(multi.simple_name(), name.to_string());
    assert_eq!(multi.serde_name(), Some(name.to_string()));
    assert_eq!(multi.strum_name().unwrap(), multi.to_string());

    assert!(!has_property(&multi, name));
    assert!(has_property(&multi, "action"));
    assert!(has_property(&multi, "payload"));
    assert!(has_property(&multi, "type"));

    let multi_type = get_type(&multi).unwrap();
    assert_eq!(multi_type, name);


    let another = StrumDisplay::AnotherJsonStruct { 
        action: Actions::Three { msg: String::from("Three") },
        another_type: "another_struct".to_string(),
        payload: "imp".to_string() 
    };

    assert!(get_type(&another).is_none());
    assert!(!has_property(&another, "type"));
    assert!(has_property(&another, "another_json_struct"));

    
    let multi : MultiTraited = serde_json::from_str(another.to_string().as_str()).unwrap();
    assert_eq!(multi.variant_name(), "another_struct");
    assert!(has_property(&multi, "type"));
    assert!(!has_property(&multi, "another_struct"));
    assert!(!has_property(&multi, "another_json_struct"));

    
    let another = StrumDisplay::AnotherJsonStruct { 
        action: Actions::One { param1: String::from("Very Tough One"), param2: 69 },
        another_type: "camel_struct".to_string(),
        payload: "important information".to_string() 
    };

    let multi : MultiTraited = serde_json::from_str(another.to_string().as_str()).unwrap();
    assert!(has_property(&multi, "type"));
    assert_eq!(get_type(&multi).unwrap(), "camel_struct");
    assert_eq!(multi.variant_name(), "camel_struct");
    assert_eq!(multi.simple_name(), "camel_struct".to_string());

}