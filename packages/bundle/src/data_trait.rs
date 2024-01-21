use saa_common::{AuthError, CredentialId, Verifiable};
use crate::{Credential, Credentials};

pub trait CredentialWrapper {

    fn credentials(&self) -> &Vec<Credential>;
    

    fn primary_index(&self) -> &Option<u8> {
        &None
    }

    fn primary(&self) -> Credential {
        let creds = self.credentials();
        if self.primary_index().is_some() {
            return creds[self.primary_index().unwrap() as usize].clone();
        } else {
            creds.first().unwrap().clone()
        }
    }

    fn secondaries(&self) -> Credentials {
        let creds = self.credentials();

        if self.primary_index().is_some() {
            creds
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != self.primary_index().unwrap() as usize)
                .map(|(_, c)| c.clone())
                .collect()
        } else {
            match creds.len() {
                0 => return vec![],
                1 => return vec![],
                _ => creds.iter().skip(1).map(|c| c.clone()).collect()
            }
        }
    }

    fn primary_id(&self) -> CredentialId {
        self.primary().id()
    }

    fn secondary_ids(&self) -> Vec<CredentialId> {
        let creds = self.credentials();

        if self.primary_index().is_some() {
            creds
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != self.primary_index().unwrap() as usize)
                .map(|(_, c)| c.id())
                .collect()
        } else {
            match creds.len() {
                0 => return vec![],
                1 => return vec![],
                _ => creds.iter().skip(1).map(|c| c.id()).collect()
                
            }
        }
    }

    fn ids(&self) -> Vec<CredentialId> {
        self.credentials().iter().map(|c| c.id()).collect()
    }

    fn names(&self) -> Vec<&'static str> {
        self.credentials().iter().map(|c| c.name()).collect()
    }

    fn values(&self) -> Vec<&dyn Verifiable> {
        self.credentials().iter().map(|c| c.value()).collect()
    }


    fn validate_credentials(&self) -> Result<(), AuthError> {
        let creds = self.credentials();

        if creds.len() == 0 {
            return Err(AuthError::NoCredentials);
        }
        if let Some(index) = self.primary_index() {
            if *index as usize >= creds.len() {
                return Err(AuthError::Generic(format!("Primary index {} is out of bounds", index)));
            }
        }
        creds.iter().map(|c| c.validate()).collect()
    }
    

    fn verify_credentials(&self) -> Result<(), AuthError> {
        self.validate_credentials()?;
        self.credentials().iter().map(|c| c.verify()).collect()
    }

}