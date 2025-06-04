mod client_data;
mod credential;

pub mod utils;
pub use credential::PasskeyCredential;
pub use saa_common::types::passkey::{PasskeyExtension, PasskeyPayload, ClientDataOtherKeys};
pub use client_data::ClientData;