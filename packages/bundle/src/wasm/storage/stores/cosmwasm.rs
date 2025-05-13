#[cfg(all(feature = "cosmwasm_1", not(feature = "cosmwasm")))]
pub use cw_storage_plus_one as cw_storage_plus;
use cw_storage_plus::{Item, Map};
use saa_common::wasm::Storage;
use serde::{de::DeserializeOwned, Serialize};
use crate::{CredentialInfo, CredentialId};

use saa_common::StorageError;


/// The credential ID to use by default for verifications
pub const VERIFYING_ID : Item<CredentialId> = Item::new("saa_verifying_id");


// whether there are native callers to authorize easily
pub const HAS_NATIVES : Item<bool> = Item::new("saa_has_natives");


/// Mapping of credential IDs to credential additional information.
pub const CREDENTIAL_INFOS: Map<CredentialId, CredentialInfo> = Map::new("saa_credentials");


/// Storage of used nonces  to prevent replay attacks. &str to boolean
#[cfg(feature = "replay")]
pub const ACCOUNT_NUMBER : Item<u64> = Item::new("saa_acc_num");



/// Storage of session keys
#[cfg(feature = "session")]
pub const SESSIONS: Map<String, crate::Session> = Map::new("saa_sessions");



// Feauture only because not used elsewhere
#[cfg(all(feature = "replay", feature = "utils"))]
pub(crate) fn item_exist<T>(
    storage: &mut dyn Storage,
    item: &Item<T>,
) -> bool 
    where T: Serialize + DeserializeOwned
{
    item.exists(storage)
}


pub(crate) fn map_has<T>(
    storage: &dyn Storage,
    map: &Map<String, T>,
    key: impl ToString,
) -> bool 
    where T: Serialize + DeserializeOwned
{
    map.has(storage, key.to_string())
}


pub(crate) fn map_get<T>(
    storage: &dyn Storage,
    map: &Map<String, T>,
    key: impl ToString,
    name: &str
) -> Result<T, StorageError> 
    where T: Serialize + DeserializeOwned
{
    map
    .load(storage, key.to_string())
    .map_err(|e| StorageError::Read(name.to_string(), e.to_string()))
}



pub(crate) fn map_save<T>(
    storage: &mut dyn Storage,
    map: &Map<String, T>,
    key: impl ToString,
    value: &T,
    name: &str
) -> Result<(), StorageError> 
    where T: Serialize + DeserializeOwned
{
    map.save(storage, key.to_string(), value)
    .map_err(|e| StorageError::Write(name.to_string(), e.to_string()))
}


#[cfg(any(feature = "iterator", feature = "session"))]
pub(crate) fn map_remove<T>(
    storage: &mut dyn Storage,
    map: &Map<String, T>,
    key: impl ToString,
) where T: Serialize + DeserializeOwned {
    map.remove(storage, key.to_string());
}



#[cfg(feature = "iterator")]
pub(crate) fn get_map_records<V>(
    storage: &dyn Storage,
    map: &Map<String, V>,
    name: &str
) -> Result<Vec<(String, V)>, StorageError> 
    where V: Serialize + DeserializeOwned
{
    map
    .range(storage, None, None, saa_common::wasm::Order::Ascending)
    .collect::<Result<Vec<(CredentialId, V)>, saa_common::wasm::StdError>>()
    .map_err(|e| StorageError::Read(name.to_string(), e.to_string()))
}


#[cfg(all(feature = "iterator", feature = "utils"))]
pub(crate) fn get_map_count<V>(
    storage: &dyn Storage,
    map: &Map<String, V>
) -> usize 
    where V: Serialize + DeserializeOwned
{
    map.keys_raw(storage, None, None, saa_common::wasm::Order::Ascending).count()
}



#[cfg(feature = "iterator")]
pub(crate) fn delete_map_records<V>(
    storage: &mut dyn Storage,
    map: &Map<String, V>,
    _: &str
) -> Result<(), StorageError> 
    where V: Serialize + DeserializeOwned
{
    map.clear(storage);
    Ok(())
}