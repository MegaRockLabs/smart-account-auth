
use core::fmt::Debug;
use saa_schema::wasm_serde;

mod replay;

use crate::{ensure, AuthError, Binary};

#[cfg(feature = "replay")]
pub use replay::*;





#[wasm_serde]
pub struct SignedDataMsg {
    pub data: Binary,
    pub signature: Binary,
    pub payload: Option<AuthPayload>,
}



#[wasm_serde]
pub struct AuthPayload<E = Binary> {
    pub hrp: Option<String>,
    pub address: Option<String>,
    pub credential_id: Option<Binary>,
    pub extension: Option<E>
}


impl<E> AuthPayload<E> {

    pub fn validate(&self) -> Result<(), AuthError> {
        let error : &str = "Only one of the 'address' or 'hrp' can be provided";

        if self.hrp.is_some() {
            ensure!(
                self.address.is_none(),
                AuthError::generic(error)
            );
        }
        if self.address.is_some() {
            ensure!(self.hrp.is_none(), AuthError::generic(error));
            let addr = self.address.clone().unwrap();
            ensure!(
                addr.len() > 3 && (addr.starts_with("0x") || addr.contains("1")),
                AuthError::generic("Invalid address")
            );
        }
        Ok(())
    }

    
}


