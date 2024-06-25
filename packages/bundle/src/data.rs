use core::fmt::Display;

#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env, MessageInfo};
#[cfg(feature = "substrate")]
use saa_common::substrate::{InkEnvironment, InkApi};

use saa_common::{Vec, vec, format};
use saa_common::{AuthError, CredentialId, Verifiable};
use saa_custom::caller::Caller;
use saa_schema::wasm_serde;

use crate::{Credential, CredentialsWrapper};


#[wasm_serde]
pub struct CredentialData<M: Display + Clone = String> {
    pub credentials     :  Vec<Credential<M>>,
    pub with_caller     :  Option<bool>,
    pub primary_index   :  Option<u8>,
}


impl<M: Display + Clone> Default for CredentialData<M> {
    fn default() -> Self {
        Self { 
            credentials     : vec![], 
            with_caller     : None,
            primary_index   : None, 
        }
    }
}

impl<M: Display + Clone> CredentialData<M> {

    pub fn new(
        credentials: Vec<Credential<M>>, 
        primary_index: Option<u8>, 
        with_caller: Option<bool>,
    ) -> Self {
        Self { 
            credentials, 
            primary_index,
            with_caller,
        }
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.credentials.iter().map(|c| c.name()).collect()
    }

    pub fn values(&self) -> Vec<&dyn Verifiable> {
        self.credentials.iter().map(|c| c.value()).collect()
    }

    pub fn find_by_name(&self, name: &str) -> Option<Credential<M>> {
        self.credentials
            .iter()
            .find(|c| c.name() == name)
            .cloned()
    }

    pub fn find_by_id(&self, id: &CredentialId) -> Option<Credential<M>> {
        self.credentials
            .iter()
            .find(|c| c.id() == *id)
            .cloned()
    }



    pub fn with_caller<C: Into::<Caller>> (&self, cal: C) -> Self {
        let mut credentials = self.credentials.clone();
        let existing = credentials.iter().position(|c| c.name() == "caller");
        if let Some(index) = existing {
            credentials[index] = Credential::Caller(cal.into());
        } else {
            credentials.push(Credential::Caller(cal.into()));
        }
        Self {
            credentials,
            with_caller: Some(true),
            primary_index: self.primary_index,
        }
    }


    #[cfg(feature = "substrate")]
    pub fn with_caller_ink(&self, id: impl AsRef<[u8]>) -> Self {
        self.with_caller(id.as_ref())
    }
    

    #[cfg(feature = "cosmwasm")]
    pub fn with_caller_cosmwasm(&self, info: &saa_common::cosmwasm::MessageInfo) -> Self  {
        self.with_caller(info)
    }

}




impl<M: Display + Clone> CredentialsWrapper for CredentialData<M> {
    type Credential = Credential<M>;

    fn credentials(&self) -> &Vec<Self::Credential> {
        &self.credentials
    }
}



impl<M: Display + Clone> Verifiable for CredentialData<M> {

    fn id(&self) -> CredentialId {
        self.primary_id()
    }

    fn validate(&self) -> Result<(), AuthError> {
        let creds = self.credentials();

        let with_caller = self.with_caller.unwrap_or(false);
        if !with_caller && creds.len() == 0 {
            return Err(AuthError::NoCredentials);
        } else if creds.len() > 255 {
            return Err(AuthError::Generic(format!("Too many credentials: {}", creds.len())));
        }

        if let Some(index) = self.primary_index() {
            let len = creds.len() + if with_caller { 1 } else { 0 };
            if *index as usize >= len {
                return Err(AuthError::Generic(format!("Primary index {} is out of bounds", index)));
            }
        }
        creds.iter().map(|c| c.validate()).collect()
    }
    

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.validate()?;
        self.credentials().iter().map(|c| c.verify()).collect()
    }


    #[cfg(feature = "substrate")]
    fn verified_ink<'a>(&self, api: InkApi<'a, impl InkEnvironment + Clone>) -> Result<Self, AuthError> {
        let with_caller = self.with_caller.unwrap_or(false);
        
        let creds = if with_caller {
            let caller = api.clone().caller();
            self.with_caller_ink(caller)
        } else {
            self.clone()
        };

        creds.validate()?;

        creds.credentials()
            .iter()
            .map(|c| c.verified_ink(api.clone())).
            collect::<Result<Vec<Credential<M>>, AuthError>>()?;

        Ok(creds.clone())
    }


    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(&self, api: &dyn Api, env: &Env, info: &Option<MessageInfo>) -> Result<Self, AuthError>
    {
        let with_caller = self.with_caller.unwrap_or(false);
        let creds = if with_caller && info.is_some() {
            self.with_caller_cosmwasm(info.as_ref().unwrap())
        } else {
            self.clone()
        };

        creds.validate()?;

        let verified = creds.credentials()
                .iter()
                .map(|c| c.verified_cosmwasm(api, env, info)).
                collect::<Result<Vec<Credential<M>>, AuthError>>()?;

        Ok(Self {
            credentials: verified,
            with_caller: self.with_caller,
            primary_index: creds.primary_index,
        })
    }

}