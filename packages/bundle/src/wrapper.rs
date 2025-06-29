use saa_common::{AuthError, CredentialId, CredentialName, Identifiable, Vec, Verifiable};
#[cfg(feature = "wasm")]
use {
    saa_common::wasm::{Deps, Env, MessageInfo},
};


/* #[derive(Clone)]
pub enum TempOption<M: serde::Serialize + core::fmt::Display + Clone> {
    None,
    Messages(Vec<M>),
}


#[derive(Clone)]
pub struct TempParams<M: serde::Serialize + core::fmt::Display + Clone> {
    pub override_id       :  Option<String>,
    pub override_address  :  Option<String>,
    pub check_inner       :  TempOption<M>,
    pub has_inners        :  bool,
    pub nonce             :  u64,
}
 */
pub trait CredentialsWrapper  {

    type Credential  : Verifiable + Clone;

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
        #[cfg(all(feature = "replay", feature = "optimise"))]
        params: ReplayParams,
        #[cfg(all(feature = "replay", not(feature = "optimise")))]
        params: ReplayParams<impl serde::Serialize + core::fmt::Display + Clone>
    ) -> Result<crate::VerifiedData, AuthError>;


/* 
    #[cfg(all(any(feature = "native", feature = "wasm"), feature = "replay", not(feature = "optimise")))]
    fn verify<M : serde::Serialize + core::fmt::Display + Clone>(&self,
        #[cfg(feature = "wasm")]
        deps: Deps, env: &Env, info: &MessageInfo,
        params: ReplayParams<M>
    ) -> Result<crate::data::VerifiedData, AuthError>;

    
    #[cfg(all(any(feature = "native", feature = "wasm"), feature = "replay", feature = "optimise"))]
    fn verify(&self,
        #[cfg(feature = "wasm")]
        deps: Deps, env: &Env, info: &MessageInfo,
        params: ReplayParams
    ) -> Result<crate::data::VerifiedData, AuthError>;



    #[cfg(all(any(feature = "native", feature = "wasm"), not(feature = "replay")))]
    fn verify(&self,
        #[cfg(feature = "wasm")]
        deps: Deps, env: &Env, info: &MessageInfo,
    ) -> Result<crate::data::VerifiedData, AuthError>;
 */
   
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



#[cfg(all(any(feature = "native", feature = "wasm"), feature = "replay"))]
use saa_crypto::ReplayParams;
#[cfg(feature = "replay")]
use saa_crypto::ReplayProtection;


#[cfg(feature = "replay")]
pub trait ReplayProtectionWrapper : CredentialsWrapper 
    where Self::Credential: ReplayProtection
{

    #[cfg(all(feature = "optimise", any(feature = "native", feature = "wasm")))]
    fn protect_reply(
        &self,
        #[cfg(feature = "wasm")]
        env: &saa_common::wasm::Env,
        params: ReplayParams,
    ) -> Result<(), saa_common::ReplayError> {
        #[cfg(not(feature = "wasm"))]
        ensure!(messages.is_some(), saa_common::ReplayError::MissingData("Messages".into()));
        self
            .credentials()
            .iter()
            .filter(|c| c.name() != CredentialName::Native)
            .try_for_each(|c| c.protect_reply(env, params.clone()))
    }


     #[cfg(all(not(feature = "optimise"), any(feature = "native", feature = "wasm")))]
    fn protect_reply<M: serde::Serialize + core::fmt::Display + Clone>(
        &self,
        #[cfg(feature = "wasm")]
        env: &saa_common::wasm::Env,
        params: ReplayParams<M>,
    ) -> Result<(), saa_common::ReplayError> {
        #[cfg(not(feature = "wasm"))]
        ensure!(messages.is_some(), saa_common::ReplayError::MissingData("Messages".into()));
        self.credentials()
            .iter()
            .filter(|c| c.name() != CredentialName::Native)
            .try_for_each(|c| c.protect_reply(env, params.clone()))
    
    }
}

