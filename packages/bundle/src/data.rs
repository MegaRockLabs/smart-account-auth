#![allow(unreachable_code)]

use saa_common::{
    format, ensure,
    CredentialId, 
    Vec, Verifiable, AuthError
};
use saa_auth::caller::Caller;
use saa_schema::wasm_serde;
use strum::IntoDiscriminant;



use crate::{credential::CredentialName, Credential, CredentialsWrapper};



#[wasm_serde]
pub struct CredentialData {
    pub credentials     :  Vec<Credential>,
    pub with_caller     :  Option<bool>,
    pub primary_index   :  Option<u8>,
}


#[wasm_serde]
pub enum UpdateOperation<A = CredentialData> {
    Add(A),
    Remove(A),
}




impl CredentialsWrapper for CredentialData {
    type Credential = Credential;

    fn credentials(&self) -> &Vec<Self::Credential> {
        &self.credentials
    }
}



impl Verifiable for CredentialData {

    fn id(&self) -> CredentialId {
        self.primary_id()
    }

    fn validate(&self) -> Result<(), AuthError> {
        let creds = self.credentials();
        let with_caller = self.with_caller.unwrap_or(false);

        if with_caller {
            ensure!(creds
                    .iter()
                    .filter(|c| c.discriminant() == CredentialName::Caller)
                    .count() == 1,
                AuthError::generic("No caller credential found")
            );
        } else if creds.len() == 0 {
            return Err(AuthError::NoCredentials);
        } else if creds.len() > 255 {
            return Err(AuthError::Generic(format!("Too many credentials: {}", creds.len())));
        }

        if let Some(index) = self.primary_index() {
            let len = creds.len() + if with_caller { 1 } else { 0 };
            if index as usize >= len {
                return Err(AuthError::Generic(format!("Primary index {} is out of bounds", index)));
            }
        }
        creds.iter().try_for_each(|c| c.validate())
    }


    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.validate()?;
        self.credentials().iter().try_for_each(|c| c.verify())
    }


    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self,  api : &dyn saa_common::wasm::Api) -> Result<(), AuthError>  {
        self.validate()?;
        self.credentials().iter().try_for_each(|c| c.verify_cosmwasm(api))
    }

}





impl CredentialData {

    pub fn with_caller<C: Into::<Caller>> (&self, cal: C) -> Self {
        let mut credentials = self.credentials.clone();

        let existing = credentials.iter()
                .position(|c| c.name() == CredentialName::Caller);

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
    pub fn with_caller_ink(&self, id: saa_common::String) -> Self {
        self.with_caller(Caller { id })
    }

}


