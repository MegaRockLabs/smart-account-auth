#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env, MessageInfo};
#[cfg(feature = "substrate")]
use saa_common::substrate::{InkEnvironment, InkApi};

use saa_common::{Vec, vec, format};
use saa_common::{AuthError, CredentialId, Verifiable};
use saa_custom::caller::Caller;
use saa_schema::wasm_serde;

use crate::{Credential, Credentials, CredentialsWrapper};


#[wasm_serde]
pub struct CredentialData {
    pub credentials     :  Credentials,
    pub with_caller     :  Option<bool>,
    pub primary_index   :  Option<u8>,
    pub secs_to_expire  :  Option<u64>
}


impl Default for CredentialData {
    fn default() -> Self {
        Self { 
            credentials     : vec![], 
            with_caller     : None,
            primary_index   : None, 
            secs_to_expire  : None
        }
    }
}

impl CredentialData {

    pub fn new(
        credentials: Credentials, 
        primary_index: Option<u8>, 
        with_caller: Option<bool>,
        secs_to_expire: Option<u64>
    ) -> Self {
        Self { 
            credentials, 
            primary_index,
            with_caller,
            secs_to_expire
        }
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.credentials().iter().map(|c| c.name()).collect()
    }

    pub fn values(&self) -> Vec<&dyn Verifiable> {
        self.credentials().iter().map(|c| c.value()).collect()
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
            secs_to_expire: self.secs_to_expire
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




impl CredentialsWrapper for CredentialData {
    type Credential = Credential;

    fn credentials(&self) -> &Vec<Credential> {
        &self.credentials
    }
}



impl Verifiable for CredentialData {

    fn id(&self) -> CredentialId {
        self.primary_id()
    }

    fn validate(&self) -> Result<(), AuthError> {
        let creds = self.credentials();

        if creds.len() == 0 {
            return Err(AuthError::NoCredentials);
        } else if creds.len() > 255 {
            return Err(AuthError::Generic(format!("Too many credentials: {}", creds.len())));
        }

        if let Some(index) = self.primary_index() {
            if *index as usize >= creds.len() {
                return Err(AuthError::Generic(format!("Primary index {} is out of bounds", index)));
            }
        }
        creds.iter().map(|c| c.validate()).collect()
    }
    

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
            collect::<Result<Vec<Credential>, AuthError>>()?;

        Ok(creds.clone())
    }


    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(&self, api: &dyn Api, env: &Env, info: &MessageInfo) -> Result<Self, AuthError> {   
        let with_caller = self.with_caller.unwrap_or(false);

        let creds = if with_caller {
            self.with_caller_cosmwasm(info)
        } else {
            self.clone()
        };

        creds.validate()?;

        creds.credentials()
                .iter()
                .map(|c| c.verified_cosmwasm(api, env, info)).
                collect::<Result<Vec<Credential>, AuthError>>()?;

        Ok(creds.clone())
    }

}