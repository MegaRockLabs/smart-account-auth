mod impls;
mod client_data;
mod credential;

pub mod utils;
pub use credential::PasskeyCredential;
pub use saa_common::types::exts::{PasskeyInfo, PasskeyPayload, ClientDataOtherKeys};
pub use client_data::ClientData;