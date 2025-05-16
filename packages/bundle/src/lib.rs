#![cfg_attr(not(feature = "std"), no_std)]
mod data;
mod credential;
mod messages;
mod impls;

#[cfg(feature = "traits")]
mod wrapper;
#[cfg(feature = "wasm")]
mod wasm;
#[cfg(feature = "native")]
pub use saa_common::crypto;


pub use saa_schema::saa_type;
pub use saa_common::{AuthError, ReplayError, StorageError, CredentialId, Verifiable, ensure};
pub use credential::{Credential, CredentialName, CredentialInfo, CredentialRecord, build_credential};
pub use data::CredentialData;


pub mod msgs {
    use super::messages as msgs;

    #[cfg(feature = "replay")]
    pub use msgs::replay::{MsgDataToSign, MsgDataToVerify};
    #[cfg(feature = "session")]
    pub use {
        msgs::actions::{Action, AllowedActions, DerivableMsg, ActionDerivation, AllQueryDerivation},
        saa_common::Empty
    };
    pub use msgs::{SignedDataMsg, AuthPayload};

}

#[cfg(feature = "session")]
pub use { 
    saa_common::{Expiration, SessionError},
    messages::sessions::{SessionInfo, Session}
};

#[cfg(all(feature = "wasm", feature = "types"))]
pub use saa_common::wasm as cosmwasm_std;
#[cfg(feature = "types")]
pub mod types {
    pub use saa_common::types::*;
    #[cfg(feature = "passkeys")]
    pub use saa_auth::passkey::{ClientData, ClientDataOtherKeys, PasskeyInfo, PasskeyPayload};
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
}


#[cfg(feature = "traits")]
pub mod traits {
    pub use super::wrapper::CredentialsWrapper;
}


// ---  Credentials  ---
pub use saa_auth::caller::Caller;
#[cfg(feature = "passkeys")]
pub use saa_auth::passkey::PasskeyCredential;
#[cfg(feature = "ethereum")]
pub use saa_auth::eth::EthPersonalSign;
#[cfg(feature = "cosmos")]
pub use saa_auth::cosmos::CosmosArbitrary;
#[cfg(feature = "ed25519" )]
pub use saa_curves::ed25519::Ed25519;
#[cfg(feature = "curves")]
pub use saa_curves::{secp256k1::Secp256k1, secp256r1::Secp256r1};