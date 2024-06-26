use saa_common::{Vec, vec, CredentialId, Verifiable};

pub trait CredentialsWrapper : Clone + Verifiable {

    type Credential         : Verifiable + Clone;


    fn credentials(&self) -> &Vec<Self::Credential>;

  
    fn primary_index(&self) -> &Option<u8> {
        &None
    }

    fn primary(&self) -> Self::Credential {
        let creds = self.credentials();
        if self.primary_index().is_some() {
            return creds[self.primary_index().unwrap() as usize].clone();
        } else {
            creds.first().unwrap().clone()
        }
    }

    fn secondaries(&self) -> Vec<Self::Credential> {
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


}
