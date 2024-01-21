#[cfg(feature = "cosmwasm")]
use saa_common::{Api, Env, MessageInfo};
use saa_common::{AuthError, CredentialId, Verifiable, Environment, DefaultEnvironment};
use saa_custom::caller::Caller;
use saa_schema::wasm_serde;
use crate::{wrapper::CredentialWrapper, Credential, Credentials};


#[wasm_serde]
pub struct CredentialData<E = DefaultEnvironment> 
where E: Environment + Clone
{
    pub credentials:   Credentials,
    pub primary_index: Option<u8>,
    pub with_caller:   Option<bool>,
    pub ink_env:       Option<E>
}


impl<E> Default for CredentialData<E> 
where E: Environment + Clone
{
    fn default() -> Self {
        Self { credentials: vec![], primary_index: None, with_caller: None, ink_env: None }
    }
}

#[allow(dead_code)]
impl<E> CredentialData<E> 
where E: Environment + Clone
{

    pub fn new(
        credentials: Credentials, 
        primary_index: Option<u8>, 
        with_caller: Option<bool>,
        ink_env: Option<E>
    ) -> Self {
        Self { 
            credentials, 
            primary_index,
            with_caller,
            ink_env
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
        Ok(Self { 
            credentials, 
            primary_index: self.primary_index,
            with_caller: self.with_caller,
            ink_env: self.ink_env.clone()
        })
    }

    #[cfg(feature = "substrate")]
    pub fn with_caller_ink(&mut self) -> Result<Self, AuthError> {
        let id = saa_common::caller::<E>();
        self.with_caller(id.as_ref())
    }

    #[cfg(feature = "cosmwasm")]
    pub fn with_caller_cosmwasm(&mut self, info: &saa_common::MessageInfo) -> Result<Self, AuthError> {
        self.with_caller(info)
    }
}



impl<E: Environment> CredentialWrapper for CredentialData<E>
where E: Environment + Clone
{
    fn credentials(&self) -> &Vec<Credential> {
        &self.credentials
    }

    fn primary_index(&self) -> &Option<u8> {
        &self.primary_index
    }
}
    


impl<E: Environment> Verifiable<E> for CredentialData<E>
where E: Environment + Clone
{

    fn id(&self) -> CredentialId {
        self.primary_id()
    }
    
    fn validate(&self) -> Result<(), AuthError> {
        self.validate_credentials()
    }

    fn verify(&self) -> Result<(), AuthError> {
        self.verify_credentials()
    }

    fn verify_ink(&mut self) -> Result<(), AuthError> {

        let id = saa_common::caller::<E>();

        if self.with_caller.is_some() && self.with_caller.unwrap() {
            self.populate_caller(id.as_ref())?
        };
        self.validate()?;
        self.credentials.iter_mut().map(|c| c.verify_ink()).collect()
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