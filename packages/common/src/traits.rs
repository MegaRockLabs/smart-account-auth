use core::ops::Deref;
use crate::{AuthError, CredentialId, CredentialInfo};


pub trait Verifiable  {

    fn id(&self) -> CredentialId;

    fn validate(&self) -> Result<(), AuthError>;

    #[cfg(any(feature = "native", feature = "wasm"))]  // temproral until others implemented
    fn verify(&self,
        #[cfg(feature = "wasm")]
        deps: crate::wasm::Deps
    ) -> Result<CredentialInfo, AuthError>;

}



impl<T: Deref<Target = dyn Verifiable>> Verifiable for T {
    
    fn id(&self) -> CredentialId {
        self.deref().id()
    }

    fn validate(&self) -> Result<(), AuthError> {
        self.deref().validate()
    }

    #[cfg(any(feature = "native", feature = "wasm"))]
    fn verify(&self,
        #[cfg(feature = "wasm")]
        deps: crate::wasm::Deps
    ) -> Result<CredentialInfo, AuthError> {
        self.deref().verify(
            #[cfg(feature = "wasm")]
            deps
        )
    }
}

