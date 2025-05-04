use saa_common::{Vec, vec, CredentialId, Verifiable};
use strum::IntoDiscriminant;

pub trait CredentialsWrapper : Clone + Verifiable {

    #[cfg(feature = "utils")]
    type Credential  : Verifiable + Clone + IntoDiscriminant<Discriminant : ToString>;
    #[cfg(not(feature = "utils"))]
    type Credential  : Verifiable + Clone;

    fn credentials(&self) -> &Vec<Self::Credential>;

    
    fn primary_index(&self) -> Option<u8> {
        None
    }

    fn primary(&self) -> Self::Credential {
        let creds = self.credentials();
        if let Some(index) = self.primary_index() {
            return creds[index as usize].clone();
        } else {
            return creds[0].clone();
        } 
    }

    fn primary_id(&self) -> CredentialId {
        self.primary().id()
    }

    #[cfg(feature = "utils")]
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
                // no ids at all
                0 => return vec![],
                // only primary id
                1 => return vec![],
                // skop primary and take the rest
                _ => creds.iter().skip(1)
                    .map(|c| c.clone()).collect()
            }
        }
    }

    #[cfg(feature = "utils")]
    fn count(&self) -> usize {
        self.credentials().len()
    }

    #[cfg(feature = "utils")]
    fn names(&self) -> Vec<String> {
        self.credentials()
            .iter()
            .map(|c| c.discriminant().to_string())
            .collect()
    }

}
