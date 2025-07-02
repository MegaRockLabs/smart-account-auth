#[cfg(feature = "replay")]
use saa_crypto::{ReplayProtection, ReplayParams};
#[cfg(feature = "wasm")]
use saa_common::wasm::{Deps, Env, MessageInfo};
use saa_common::{AuthError, CredentialId, CredentialName, Identifiable, Vec};


pub trait CredentialsWrapper  {
    #[cfg(not(feature = "replay"))]
    type Credential  : saa_common::Verifiable + Clone;
    #[cfg(feature = "replay")]
    type Credential  : ReplayProtection + Clone;

    fn credentials(&self) -> &Vec<Self::Credential>;

     fn primary_index(&self) -> Option<usize> {
        None
    }

    fn validate(&self, sender: impl AsRef<str> )-> Result<(), AuthError>;


    #[cfg(any(feature = "native", feature = "wasm"))]
    fn verify(&self,
        #[cfg(feature = "wasm")]
        deps: Deps, env: &Env, info: &MessageInfo,
        #[cfg(not(feature = "wasm"))]
        sender: String,
        #[cfg(feature = "replay")]
        params: ReplayParams,
    ) -> Result<crate::VerifiedData, AuthError>;


   
    fn primary(&self) -> &Self::Credential {
        let creds = self.credentials();
        if let Some(index) = self.primary_index() {
            return &creds[index];
        } else {
            return &creds[0];
        } 
    }

    fn primary_id(&self) -> CredentialId {
        self.primary().id()
    }

    
    #[cfg(feature = "utils")]
    fn count(&self) -> usize {
        self.credentials().len()
    }

    #[cfg(feature = "utils")]
    fn names(&self) -> Vec<String> {
        self.credentials()
            .iter()
            .map(|c| c.name().to_string())
            .collect()
    }

    #[cfg(feature = "utils")]
    fn secondaries(&self) -> Vec<&Self::Credential> {
        use saa_common::vec;
        if self.count() <= 1 { return vec![] };
        let primary_id = self.primary_id().to_lowercase();
        self.credentials()
            .into_iter()
            .filter(|c| c.id() != primary_id)
            .collect()
    }


    fn cred_index(
        &self, 
        id: &CredentialId,
        name: CredentialName
    ) -> Option<usize> {
        self.credentials().iter()
            .position(|c| c.name() == name && *id == c.id())
    }

    
}
