
use core::fmt::Debug;
use saa_schema::wasm_serde;


use crate::{Binary, CredentialId};

#[cfg(feature = "replay")]
mod replay;

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
    pub credential_id: Option<CredentialId>,
    pub extension: Option<E>
}
