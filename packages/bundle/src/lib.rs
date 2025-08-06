#![cfg_attr(not(feature = "std"), no_std)]
use saa_common::{cfg_mod_pub, cfg_mod_use, mod_use};


mod wrapper;
mod caller;
mod messages;
mod impls;
mod traits;

mod_use!(data);
mod_use!(credential);
cfg_mod_pub!("utils", utils);
cfg_mod_pub!("types", types);
cfg_mod_use!("wasm", wasm);


pub use traits::*;
pub use saa_schema::{saa_type, saa_derivable};
pub use saa_common::{types::errors, Expiration};
pub use errors::AuthError;


#[cfg(feature = "session")]
pub use {messages::sessions::{Session, SessionInfo}, saa_common::SessionError};
#[cfg(feature = "replay")]
pub use {saa_crypto::{CheckOption, ReplayParams}};
#[cfg(feature = "native")]
pub use saa_crypto as crypto;

pub mod msgs {
    #[cfg(feature = "session")]
    pub use super::messages::actions::{Action, ActionDerivation, AllQueryDerivation, AllowedActions};
    #[cfg(feature = "replay")]
    pub use saa_common::types::signed::{MsgDataToSign, MsgDataToVerify};
    pub use saa_common::types::signed::{SignedDataMsg, AuthPayload};
}