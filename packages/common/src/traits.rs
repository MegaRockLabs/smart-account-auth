use core::ops::Deref;
use std::borrow::Cow;

use crate::{AuthError, CredentialId, CredentialName};


pub trait Identifiable {
    fn id(&self) -> CredentialId;
    fn name(&self) -> CredentialName;
}



pub trait Verifiable : Identifiable  {

    fn message(&self) -> Cow<[u8]>;

    fn validate(&self) -> Result<(), AuthError>;

    #[cfg(any(feature = "native", feature = "wasm"))]  
    fn verify(&self,
        #[cfg(feature = "wasm")]
        deps: crate::wasm::Deps
    ) -> Result<crate::CredentialInfo, AuthError>;

}


impl<T: Deref<Target = dyn Identifiable>> Identifiable for T {
    fn id(&self) -> CredentialId {
        self.deref().id()
    }

    fn name(&self) -> CredentialName {
        self.deref().name()
    }
}



impl<T: Deref> Verifiable for T 
    where 
        T: Identifiable,
        T::Target: Identifiable + Verifiable
{
    
    fn validate(&self) -> Result<(), AuthError> {
        self.deref().validate()
    }

    #[cfg(any(feature = "native", feature = "wasm"))]
    fn verify(&self,
        #[cfg(feature = "wasm")]
        deps: crate::wasm::Deps
    ) -> Result<crate::CredentialInfo, AuthError> {
        self.deref().verify(
            #[cfg(feature = "wasm")]
            deps
        )
    }
    
    fn message(&self) -> Cow<[u8]> {
        self.deref().message()
    }
}



