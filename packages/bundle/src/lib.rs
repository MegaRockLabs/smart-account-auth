#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "traits")]
mod wrapper;
#[cfg(feature = "wasm")]
mod wasm;
mod caller;
mod credential;
mod messages;
mod impls;
mod data;


pub use saa_schema::{saa_type, saa_derivable};
pub use saa_common::{AuthError, StorageError, CredentialId, ensure};
pub use data::CredentialData;
pub use credential::*;


pub mod msgs {
    pub use saa_common::types::msgs::{SignedDataMsg, AuthPayload};
    #[cfg(feature = "replay")]
    pub use super::messages::replay::{MsgDataToSign, MsgDataToVerify};
    #[cfg(feature = "session")]
    pub use {super::messages::actions::{
        Action, AllowedActions, ActionDerivation, AllQueryDerivation
    }};
}

#[cfg(feature = "replay")]
pub use saa_common::ReplayError;
#[cfg(feature = "native")]
pub use saa_crypto as crypto;
#[cfg(feature = "session")]
pub use { 
    saa_common::{Expiration, SessionError},
    messages::sessions::{SessionInfo, Session}
};
#[cfg(feature = "types")]
pub mod types {
    pub use saa_common::types::*;
    #[cfg(feature = "passkeys")]
    pub use saa_passkeys::passkey::{
        ClientData, ClientDataOtherKeys, PasskeyInfo, PasskeyPayload
    };
    #[cfg(feature = "session")]
    pub use super::messages::actions::{ActionDerivation, AllQueryDerivation};
}
#[cfg(all(feature = "wasm", feature = "types"))]
pub use saa_common::wasm as cosmwasm_std;


#[cfg(feature = "utils")]
pub mod utils {
    pub use saa_crypto::hashes;
    #[cfg(feature = "cosmos")]
    pub use saa_auth::cosmos::utils as cosmos;
    #[cfg(feature = "ethereum")]
    pub use saa_auth::eth::utils as eth;
    #[cfg(feature = "passkeys")]
    pub use saa_passkeys::passkey::utils as passkey;
}

#[cfg(feature = "traits")]
pub use {wrapper::CredentialsWrapper, saa_common::Verifiable};
#[cfg(all(feature = "traits", feature = "session"))]
pub use messages::actions::DerivableMsg;