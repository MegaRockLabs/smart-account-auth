use core::ops::Deref;
use std::borrow::Cow;
use crate::{AuthError, CredentialId, CredentialInfo};





pub trait Verifiable  {

    fn id(&self) -> CredentialId;

    fn message(&self) -> Cow<[u8]>;

    fn validate(&self) -> Result<(), AuthError>;

    // temp until others are simplemented
    #[cfg(any(feature = "native", feature = "wasm"))]  
    fn verify(&self,
        #[cfg(feature = "wasm")]
        deps: crate::wasm::Deps
    ) -> Result<CredentialInfo, AuthError>;

}





impl<T: Deref<Target = dyn Verifiable>> Verifiable for T {
    
    fn id(&self) -> CredentialId {
        self.deref().id()
    }

    fn message(&self) -> Cow<[u8]> {
        self.deref().message()
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

