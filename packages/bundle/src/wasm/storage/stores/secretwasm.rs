use secret_toolkit::storage::{Item, Keymap};
use crate::{CredentialInfo, CredentialId};
use serde::{de::DeserializeOwned, Serialize};
use saa_common::wasm::Storage;


use saa_common::StorageError;

/// The credential ID to use by default for verifications
pub const VERIFYING_CRED_ID : Item<CredentialId> = Item::new(b"saa_verifying_id");


// whether there are native callers to authorize easily
pub const HAS_NATIVES : Item<bool> = Item::new(b"saa_has_natives");


/// Mapping of credential IDs to credential additional information.
pub const CREDENTIAL_INFOS: Keymap<CredentialId, CredentialInfo> = Keymap::new(b"saa_credentials");


/// Storage of used nonces  to prevent replay attacks. &str to boolean
#[cfg(feature = "replay")]
pub const ACCOUNT_NUMBER : Item<u64> = Item::new(b"saa_acc_num");


/// Storage of session keys
#[cfg(feature = "session")]
pub const SESSIONS: Keymap<String, crate::Session> = Keymap::new(b"saa_sessions");



pub(crate) fn item_exist<T>(
    storage: &mut dyn Storage,
    item: &Item<T>,
) -> bool 
    where T: Serialize + DeserializeOwned
{
    item.is_empty(storage)
}


pub(crate) fn map_has<T>(
    storage: &dyn Storage,
    map: &Keymap<String, T>,
    key: &String,
) -> bool 
    where T: Serialize + DeserializeOwned
{
    map.contains(storage, key)
}


pub(crate) fn map_get<T>(
    storage: &dyn Storage,
    map: &Keymap<String, T>,
    key: &String,
    name: &str
) -> Result<T, StorageError> 
    where T: Serialize + DeserializeOwned
{
    map
    .get(storage, key)
    .map_err(|e| StorageError::Read(name.to_string(), e.to_string()))
}


pub(crate) fn map_save<T>(
    storage: &mut dyn Storage,
    map: &Keymap<String, T>,
    key: &String,
    value: &T,
    name: &str
) -> Result<(), StorageError> 
    where T: Serialize + DeserializeOwned
{
    map
    .insert(storage, key, value)
    .map_err(|e| StorageError::Write(name.to_string(), e.to_string()))
}


pub(crate) fn map_remove<T>(
    storage: &mut dyn Storage,
    map: &Keymap<String, T>,
    key: &String,
) where T: Serialize + DeserializeOwned {
    map.remove(storage, key);
}



#[cfg(feature = "iterator")]
pub(crate) fn get_map_records<V>(
    storage: &dyn Storage,
    map: &Keymap<String, V>,
    name: &str
) -> Result<Vec<(String, V)>, saa_common::StorageError> 
    where V: Serialize + DeserializeOwned
{
    map
    .iter(storage)?
    .collect::<Result<Vec<(String, V)>, saa_common::wasm::StdError>>()
    .map_err(|e| saa_common::StorageError::Read(name.to_string(), e.to_string()))
}


#[cfg(feature = "iterator")]
pub(crate) fn get_map_count(
    storage: &dyn Storage,
    map: &Keymap<String, V>,
) -> usize 
    where V: Serialize + DeserializeOwned
{
    map.get_len(storage).unwrap_or(0) as usize
}


// TODO: change to try each later or even better to solution without an error
#[cfg(feature = "iterator")]
pub(crate) fn delete_map_records(
    storage: &mut dyn Storage,
    map: &Keymap<String, V>,
    name: &str
) -> Result<(), StorageError> {
    let keys : Vec<String> = map
        .iter_keys(storage)
        .map_err(|e| StorageError(name.to_string(), e.to_string()))?
        .map(|k| k.unwrap())
        .collect();

    for key in keys {
        map.remove(storage, &key)?;
    }
    Ok(())
}