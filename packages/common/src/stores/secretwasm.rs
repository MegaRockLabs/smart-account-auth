#![allow(dead_code)]

use secret_toolkit::storage::{Item, Keymap};
use crate::{CredentialInfo, CredentialId};

/// The credential ID to use by default for verifications
pub const VERIFYING_CRED_ID : Item<CredentialId> = Item::new(b"saa_verifying_id");


/// Mapping of credential IDs to credential additional information.
pub const CREDENTIAL_INFOS: Keymap<CredentialId, CredentialInfo> = Keymap::new(b"saa_credentials");


/// An EOA address that is authorized to actions withoit any signature
pub const CALLER : Item<Option<String>> = Item::new(b"saa_with_caller");

/// Storage of used nonces  to prevent replay attacks. &str to boolean
#[cfg(feature = "replay")]
pub const ACCOUNT_NUMBER : Item<u128> = Item::new(b"saa_acc_num");
