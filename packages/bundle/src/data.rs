#[cfg(feature = "cosmwasm")]
use saa_common::{Api, Env, MessageInfo};
use saa_common::{AuthError, CredentialId, Verifiable};
use saa_custom::caller::Caller;
use saa_schema::wasm_serde;
use crate::{wrapper::CredentialWrapper, Credential, Credentials};


#[wasm_serde]
pub struct CredentialData {
    pub credentials:  Credentials,
    pub primary_index: Option<u8>,
    pub with_caller:   Option<bool>
}

impl Default for CredentialData {
    fn default() -> Self {
        Self { credentials: vec![], primary_index: None, with_caller: None }
    }
}

#[allow(dead_code)]
impl CredentialData {
    
    pub fn new(credentials: Credentials, primary_index: Option<u8>, with_caller: Option<bool>) -> Self {
        Self { 
            credentials, 
            primary_index,
            with_caller,
        }
    }

    pub fn populate_caller<C: Into::<Caller>> (&mut self, cal: C) -> Result<(), AuthError> {
        let existing = self.credentials.iter().position(|c| c.name() == "caller");
        if let Some(index) = existing {
            self.credentials[index] = Credential::Caller(cal.into());
        } else {
            self.credentials.push(Credential::Caller(cal.into()));
        }
        Ok(())
    }

    pub fn with_caller<C: Into::<Caller>> (&self, cal: C) -> Result<Self, AuthError> {
        let mut credentials = self.credentials().clone();
        let existing = credentials.iter().position(|c| c.name() == "caller");
        
        if let Some(index) = existing {
            credentials[index] = Credential::Caller(cal.into());
        } else {
            credentials.push(Credential::Caller(cal.into()));
        }
        Ok(Self { credentials, ..self.clone()})
    }

    #[cfg(feature = "cosmwasm")]
    pub fn with_caller_cosmwasm(&mut self, info: &saa_common::MessageInfo) -> Result<Self, AuthError> {
        self.with_caller(info)
    }
    
}


impl CredentialWrapper for CredentialData {  
    fn credentials(&self) -> &Vec<Credential> {
        &self.credentials
    }

    fn primary_index(&self) -> &Option<u8> {
        &self.primary_index
    }
}


impl Verifiable for CredentialData {

    fn id(&self) -> CredentialId {
        self.primary_id()
    }
    
    fn validate(&self) -> Result<(), AuthError> {
        self.validate_credentials()
    }

    fn verify(&self) -> Result<(), AuthError> {
        self.verify_credentials()
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&mut self, api: &dyn Api, env: &Env, info: &MessageInfo) -> Result<(), AuthError> {
        if self.with_caller.is_some() && self.with_caller.unwrap() {
            self.populate_caller(info)?
        };
        self.validate()?;
        self.credentials.iter_mut().map(|c| c.verify_cosmwasm(api, env, info)).collect()
    }
}

