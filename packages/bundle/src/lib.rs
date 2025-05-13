#![cfg_attr(not(feature = "std"), no_std)]
mod data;
mod credential;
mod messages;
mod impls;
#[cfg(feature = "traits")]
mod wrapper;
#[cfg(feature = "wasm")]
mod wasm;
#[cfg(feature = "session")]
mod sessions;
#[cfg(feature = "native")]
pub use saa_common::crypto;
#[cfg(feature = "derive")]
pub use saa_schema as schema;
#[cfg(all(feature = "wasm", feature = "derive"))]
pub use saa_common::wasm as cosmwasm_std;
#[cfg(all(feature = "wasm", feature = "storage"))]
pub use wasm::{storage_methods as storage, top_methods::*};

#[cfg(feature = "replay")]
pub(crate) use messages::utils::*;

pub use saa_schema::wasm_serde;
pub use saa_common::{AuthError, CredentialId};
pub use credential::{Credential, CredentialName, CredentialInfo, CredentialRecord};
pub use data::*;


pub mod msgs {
    use super::messages as msgs;

    #[cfg(feature = "replay")]
    pub use msgs::replay::{MsgDataToSign, MsgDataToVerify};
    #[cfg(feature = "session")]
    pub use {
        super::sessions::actions::{
            CreateSession, CreateSessionFromMsg, RevokeKeyMsg, WithSessionMsg,
            SessionActionMsg, SessionActionName, SessionActionsMatch,
        },
        msgs::actions::{Action, ActionMsg, AllowedActions, DerivationMethod}
    };
    pub use msgs::{SignedDataMsg, AuthPayload};

    #[cfg(all(feature = "utils", feature = "replay"))]
    pub use msgs::utils::{convert, convert_validate, convert_validate_return};

}


#[cfg(feature = "session")]
pub use {
    sessions::{Session, SessionInfo}, 
    saa_common::{Expiration, SessionError},
    saa_schema::session_action
};

#[cfg(feature = "session")]
pub mod session {
    #[cfg(all(feature = "wasm", feature = "storage"))]
    pub use super::wasm::session_methods::*;
}


#[cfg(feature = "types")]
pub mod types {
    pub use saa_common::types::*;
    #[cfg(feature = "passkeys")]
    pub use saa_auth::passkey::ClientData;
    #[cfg(feature = "storage")]
    pub use super::credential::CredentialRecord;
}


#[cfg(feature = "utils")]
pub mod utils {
    pub use saa_common::hashes;
    pub use saa_common::utils::*;
    #[cfg(feature = "cosmos")]
    pub use saa_auth::cosmos::utils as cosmos;
    #[cfg(feature = "ethereum")]
    pub use saa_auth::eth::utils as eth;
    #[cfg(feature = "passkeys")]
    pub use saa_auth::passkey::utils as passkey;
    pub use super::credential::construct_credential;
}


#[cfg(feature = "traits")]
pub mod traits {
    #[cfg(feature = "session")]
    pub use super::messages::actions::DerivableMsg;
    pub use super::wrapper::CredentialsWrapper;
    pub use saa_common::Verifiable;
}


// ---  Credentials  ---
pub use saa_auth::caller::Caller;
#[cfg(feature = "passkeys")]
pub use saa_auth::passkey::PasskeyCredential;
#[cfg(feature = "ethereum")]
pub use saa_auth::eth::EthPersonalSign;
#[cfg(feature = "cosmos")]
pub use saa_auth::cosmos::CosmosArbitrary;
#[cfg(feature = "curves")]
pub use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1, secp256r1::Secp256r1};
#[cfg(all(not(feature = "curves"), feature = "ed25519" ))]
pub use saa_curves::ed25519::Ed25519;