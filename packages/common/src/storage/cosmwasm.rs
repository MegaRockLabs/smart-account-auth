use cw_storage_plus::{Item, Map};
use crate::{CredentialInfo, CredentialId};


/// The credential ID to use by default for verifications
pub static VERIFYING_CRED_ID : Item<CredentialId> = Item::new("saa_verifying_id");


/// Mapping of credential IDs to credential additional information.
pub static CREDENTIAL_INFOS: Map<CredentialId, CredentialInfo> = Map::new("saa_credentials");


/// Storage of used nonces to prevent replay attacks.
pub static NONCES : Map<String, bool> = Map::new("saa_nonces");