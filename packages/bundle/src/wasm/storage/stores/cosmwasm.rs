#[cfg(all(feature = "cosmwasm_1", not(feature = "cosmwasm")))]
pub use cw_storage_plus_one as cw_storage_plus;


use cw_storage_plus::{Item, Map};


use crate::{CredentialInfo, CredentialId};

/// The credential ID to use by default for verifications
pub const VERIFYING_CRED_ID : Item<CredentialId> = Item::new("saa_verifying_id");


// whether there are native callers to authorize easily
pub const HAS_NATIVES : Item<bool> = Item::new("saa_has_natives");


/// Mapping of credential IDs to credential additional information.
pub const CREDENTIAL_INFOS: Map<CredentialId, CredentialInfo> = Map::new("saa_credentials");


/// Storage of used nonces  to prevent replay attacks. &str to boolean
#[cfg(feature = "replay")]
pub const ACCOUNT_NUMBER : Item<u128> = Item::new("saa_acc_num");


