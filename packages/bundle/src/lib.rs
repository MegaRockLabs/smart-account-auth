#![cfg_attr(not(feature = "std"), no_std)]


mod wrapper;
mod caller;
mod messages;
mod impls;
mod traits;

// declare and use *
mod_use!(data);
mod_use!(credential);
// conditional declare and use *
cfg_mod_pub!("utils", utils);
cfg_mod_pub!("types", types);
// declared public if enabled and private otherwise
cfg_mod_use!("wasm", wasm);



pub use traits::*;
pub use saa_schema::{saa_type, saa_derivable};
pub use saa_common::types::errors;
pub use errors::AuthError;

use saa_common::{cfg_mod_pub, cfg_mod_use, mod_use};


pub mod msgs {
    #[cfg(feature = "session")]
    pub use super::messages::actions::{Action, ActionDerivation, AllQueryDerivation, AllowedActions};
    #[cfg(feature = "replay")]
    pub use saa_common::types::signed::{MsgDataToSign, MsgDataToVerify};
    pub use saa_common::types::signed::{SignedDataMsg, AuthPayload};
}


#[cfg(feature = "native")]
pub use saa_crypto as crypto;


#[cfg(feature = "session")]
pub use { 
    saa_common::{Expiration, SessionError},
    messages::sessions::{SessionInfo, Session}
};

#[cfg(feature = "replay")]
pub use {
    saa_crypto::{CheckOption, ReplayParams}
};
