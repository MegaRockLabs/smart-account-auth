use crate::{AuthError, CredentialId};

pub trait Verifiable  {

    fn id(&self) -> CredentialId;

    fn hrp(&self) -> Option<String> {
        None
    }

    fn validate(&self) -> Result<(), AuthError>;

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError>;


    #[cfg(feature = "substrate")]
    fn verify_ink<'a>(&self,  _ : crate::substrate::InkApi<'a, impl crate::substrate::InkEnvironment>) -> Result<(), AuthError> 
        where Self: Sized 
    {
        #[cfg(feature = "native")]
        {
            self.verify()?;
            return Ok(());
        } 
        #[cfg(not(feature = "native"))]
        Err(AuthError::generic("Not implemented"))
    }


    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self,  _:  &dyn crate::wasm::Api) -> Result<(), AuthError>  
        where Self: Sized 
    {
        #[cfg(feature = "native")]
        {
            self.verify()?;
            return Ok(());
        }
        #[cfg(not(feature = "native"))]
        Err(AuthError::generic("Not implemented"))
    }

}


#[cfg(feature = "session")]
pub trait ActionName {
    fn action_name(&self) -> String;
}