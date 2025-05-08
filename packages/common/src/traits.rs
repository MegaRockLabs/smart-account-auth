use core::ops::Deref;

use crate::{AuthError, CredentialId};

pub trait Verifiable  {

    fn id(&self) -> CredentialId;

    fn hrp(&self) -> Option<String> {
        None
    }
    

    fn validate(&self) -> Result<(), AuthError>;

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError>;


    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self,  _:  &dyn crate::wasm::Api) -> Result<(), AuthError>  {
        #[cfg(feature = "native")]
        {
            self.verify()?;
            return Ok(());
        }
        #[cfg(not(feature = "native"))]
        Err(AuthError::generic("Not implemented"))
    }

}




impl<T: Deref<Target = dyn Verifiable>> Verifiable for T {
    
    fn id(&self) -> CredentialId {
        self.deref().id()
    }

    fn hrp(&self) -> Option<String> {
        self.deref().hrp()
    }

    fn validate(&self) -> Result<(), AuthError> {
        self.deref().validate()
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.deref().verify()
    }

    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self, api: &dyn crate::wasm::Api) -> Result<(), AuthError> {
        self.deref().verify_cosmwasm(api)
    }
}

