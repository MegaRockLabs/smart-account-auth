use saa_common::{AuthError, CredentialId, CredentialName, Identifiable, Vec, Verifiable};



pub trait CredentialsWrapper  {

    type Credential  : Verifiable + Clone;

    fn credentials(&self) -> &Vec<Self::Credential>;

     fn primary_index(&self) -> Option<usize> {
        None
    }

    fn validate(&self, sender: impl AsRef<str> )-> Result<(), AuthError>;

    

    #[cfg(all(any(feature = "native", feature = "wasm"), feature = "replay"))]
    fn verify<M>(&self,
        #[cfg(feature = "wasm")]
        deps: saa_common::wasm::Deps, env: &saa_common::wasm::Env, info: &saa_common::wasm::MessageInfo,
        messages: &Option<Vec<M>>,
    ) -> Result<crate::data::VerifiedData, AuthError>
    where M: serde::Serialize + core::fmt::Display + Clone;


    #[cfg(all(any(feature = "native", feature = "wasm"), not(feature = "replay")))]
    fn verify(&self,
        #[cfg(feature = "wasm")]
        deps: saa_common::wasm::Deps, env: &saa_common::wasm::Env, info: &saa_common::wasm::MessageInfo,
    ) -> Result<crate::data::VerifiedData, AuthError>;

   
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
    fn secondaries(&self) -> Vec<Self::Credential> {
        use saa_common::vec;
        let creds = self.credentials();
        if creds.len() <= 1 { return vec![] };
        let primary_id = self.primary_id();
        creds
            .into_iter()
            .filter(|c| c.id() != primary_id)
            .cloned()
            .collect::<Vec<_>>()
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



#[cfg(feature = "replay")]
use saa_crypto::ReplayProtection;


#[cfg(feature = "replay")]
pub trait ReplayProtectionWrapper : CredentialsWrapper 
    where Self::Credential: ReplayProtection
{

    fn signed_nonce(&self) -> u64;


    #[cfg(any(feature = "native", feature = "wasm"))]
    fn check_replay<M: serde::Serialize + core::fmt::Display + Clone>(
        &self,
        #[cfg(feature = "wasm")]
        env: &saa_common::wasm::Env,
        messages: &Option<Vec<M>>,
        nonce: u64,
    ) -> Result<(), saa_common::ReplayError> {
        use saa_common::{ensure, ReplayError};
        #[cfg(not(feature = "wasm"))]
        ensure!(messages.is_some(), ReplayError::MissingData("Messages".into()));
        ensure!(self.signed_nonce() == nonce, ReplayError::InvalidNonce(nonce));    
        self
            .credentials()
            .iter()
            .filter(|c| c.name() != CredentialName::Native)
            .try_for_each(|c| c.check_replay(env, messages, nonce))
                
    }
    
}

