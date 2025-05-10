#[cfg(feature = "replay")]
mod replay;
#[cfg(feature = "session")]
mod action;
#[cfg(feature = "session")]
mod session;

#[cfg(feature = "replay")]
pub use replay::*;
#[cfg(feature = "session")]
pub use action::*;
#[cfg(feature = "session")]
pub use session::*;


use saa_schema::wasm_serde;
use saa_common::{Binary, CredentialId};



#[wasm_serde]
pub struct SignedDataMsg {
    pub data: Binary,
    pub signature: Binary,
    pub payload: Option<AuthPayload>,
}



#[wasm_serde]
pub struct AuthPayload {
    pub hrp: Option<String>,
    pub credential_id: Option<CredentialId>,
    pub extension: Option<Binary>
}
