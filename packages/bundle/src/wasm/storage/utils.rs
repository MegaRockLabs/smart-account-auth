

use saa_common::{wasm::{Storage, Api}, AuthError};

use super::stores::{
    map_get, 
    VERIFYING_ID, CREDENTIAL_INFOS as CREDS
};
use crate::{
    credential::construct_credential, 
    msgs::SignedDataMsg, 
    Credential
};


#[cfg(feature = "session")]
use {
    super::stores::SESSIONS,
    crate::Session,
};

#[cfg(feature = "session")]
pub fn update_session(
    storage: &mut dyn Storage,
    key: &String,
    session: &Session,
) -> Result<(), saa_common::StorageError> {
    #[cfg(feature = "replay")]
    let session = match map_get(storage, &SESSIONS, key, "session key") {
        Ok(loaded) => &Session { nonce: loaded.nonce + 1, ..session.clone() },
        Err(_) => session,
    };
    super::stores::map_save(storage, &SESSIONS, &key, session, "session key")
}





#[cfg(feature = "utils")]
pub fn has_credential(
    storage: &dyn Storage,
    id: &saa_common::CredentialId
) -> bool {
    super::stores::map_has(storage, &CREDS, id)
}




 fn parse_cred_args(
    id: &str,
    msg: &SignedDataMsg
) -> (String, Option<String>, Option<saa_common::Binary>) {
    match &msg.payload {
        Some(payload) => {
            let id = match &payload.credential_id {
                Some(id) => id.to_lowercase(),
                None => id.to_string(),
            };
            (id, payload.hrp.clone(), payload.extension.clone())
            
        }   
        None => (id.to_string(), None, None)
    }
}


pub fn cred_from_signed(
    api : &dyn Api,
    storage:  &dyn Storage,
    msg: SignedDataMsg,
) -> Result<Credential, AuthError> {
    let (id, hrp, ext) = parse_cred_args(
        VERIFYING_ID.load(storage).map_err(|_| AuthError::NoCredentials)?.as_str(),
        &msg
    );
    let mut info = map_get(storage, &CREDS, &id, "credential")?;
    info.hrp = hrp.or(info.hrp);
    let cred = construct_credential((id, info), msg, ext)?;
    cred.verify_cosmwasm(api)?;
    Ok(cred)
}



#[cfg(feature = "session")]
pub fn session_cred_from_signed(
    api : &dyn Api,
    storage:  &dyn Storage,
    key: &str,
    msg: SignedDataMsg,
) -> Result<Credential, AuthError> {
    let (id, hrp, ext) = parse_cred_args( key, &msg);
    let session = map_get(storage, &super::stores::SESSIONS, &id, "session key")?;
    let mut info = session.grantee.1.clone();
    info.hrp = hrp.or(info.hrp);
    let cred = construct_credential((id, info), msg, ext)?;
    cred.verify_cosmwasm(api)?;
    Ok(cred)
}