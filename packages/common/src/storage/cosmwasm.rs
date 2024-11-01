use cw_storage_plus::{Item, Map};
use crate::{CredentialInfo, CredentialId};


/// The credential ID to use by default for verifications
pub static VERIFYING_CRED_ID : Item<CredentialId> = Item::new("saa_verifying_id");


/// Mapping of credential IDs to credential additional information.
pub static CREDENTIAL_INFOS: Map<CredentialId, CredentialInfo> = Map::new("saa_credentials");


/// An EOA address that is authorized to actions withoit any signature
pub static CALLER : Item<Option<String>> = Item::new("saa_with_caller");

/// Storage of used nonces  to prevent replay attacks. &str to boolean
#[cfg(feature = "replay")]
pub static NONCES : Map<&str, bool> = Map::new("saa_nonces");