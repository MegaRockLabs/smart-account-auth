mod client_data;
mod credential;

pub mod utils;
pub use credential::{PasskeyCredential, PasskeyInfo};
pub use client_data::{ClientData, ClientDataOtherKeys, PasskeyPayload};