use core::fmt::Debug;

use crate::{
    credential::{CredentialName, Credential}, 
    messages::{
        actions::{ActionMsg, DerivableMsg}, 
        SignedDataMsg,
    },
    sessions::{actions::SessionActionMsg, Session}, 
};
use saa_auth::caller::Caller;
use saa_common::{
    ensure, wasm::{Api, Env, MessageInfo, Storage}, 
    AuthError, SessionError, Verifiable
};
use super::{
    stores::{map_get, map_remove, SESSIONS}, 
    update_session, session_cred_from_signed
};




#[cfg(all(feature = "iterator", feature = "utils"))]
pub fn get_session_records(
    storage: &dyn Storage,
) -> Result<Vec<(String, Session)>, saa_common::StorageError> {
    super::stores::get_map_records(storage, &SESSIONS, "session keys")
}


#[cfg(feature = "multimsg")]
type ReturnMsg<D> = Vec<D>;
#[cfg(not(feature = "multimsg"))]
type ReturnMsg<D> = Option<D>;

type VerifyResult<D> = Result<ReturnMsg<D>, AuthError>;

fn default_return_msg<D>() -> ReturnMsg<D> {
    #[cfg(feature = "multimsg")]
    {
        vec![]
    }
    #[cfg(not(feature = "multimsg"))]
    {
        None
    }
}

fn wrap_one_rmsg<D>(msg: D) -> ReturnMsg<D> {
    #[cfg(feature = "multimsg")]
    {
        vec![msg]
    }
    #[cfg(not(feature = "multimsg"))]
    {
        Some(msg)
    }
}


fn verify_common<D: DerivableMsg>(
    session: &Session,
    cred    : &Credential,
    msgs    : Vec<D> 
) -> VerifyResult<D> {
    let (id, info) = session.grantee.clone();
    ensure!(info.name == CredentialName::Native, SessionError::InvalidGrantee);
    ensure!(id == cred.id(), SessionError::NotGrantee);
    #[cfg(feature = "multimsg")]
    {
        ensure!(msgs.iter().all(|m| session.can_do_msg(m)), SessionError::NotAllowedAction);
        return Ok(msgs)
    }
    #[cfg(not(feature = "multimsg"))]
    {
        ensure!(msgs.len() == 1, SessionError::InvalidActions);
        let msg = msgs[0].clone();
        ensure!(session.can_do_msg(&msg), SessionError::NotAllowedAction);
        return Ok(Some(msg))
    }
}


pub fn verify_session_native<D : DerivableMsg>(
    api: &dyn Api,
    address: &str,
    session: &Session,
    msg: D
) -> VerifyResult<D> {
    let cred = Caller::from(address);
    cred.verify_cosmwasm(api)?;
    verify_common( &session, &cred.into(), vec![msg])
}


#[cfg(feature = "replay")]
pub fn verify_session_signed<T : serde::de::DeserializeOwned + DerivableMsg>(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    key: &str,
    session: &Session,
    msg: SignedDataMsg
) -> VerifyResult<T> {

    let signed : crate::msgs::MsgDataToSign<T> = crate::convert_validate_return(
        msg.data.as_slice(), 
        env, 
        session.nonce
    )?;
    let cred = session_cred_from_signed(api, storage,  key, msg)?;
    
    let res = verify_common(&session, &cred, signed.messages)?;
    
    super::stores::map_save(storage, &SESSIONS, key, &Session {
        nonce: session.nonce + 1,
        ..session.clone()
    }, "session key")?;

    Ok(res)
}


#[cfg(not(feature = "replay"))]
pub fn verify_session_signed<T : serde::de::DeserializeOwned + DerivableMsg>(
    api: &dyn Api,
    storage: &dyn Storage,
    _env: &Env,
    key: &str,
    session: &Session,
    msg: SignedDataMsg
) -> VerifyResult<T> {
    let res : ReturnMsg<T> =  crate::messages::utils::convert(msg.data.as_slice(), "Action Msg")?;
    let cred = session_cred_from_signed(api, storage,  key, msg)?;
    verify_common(
        &session, 
        &cred,
        #[cfg(feature = "multimsg")]
        res,
        #[cfg(not(feature = "multimsg"))]
        vec![res.unwrap()]
    )
}





pub fn handle_actions<M>(
    api : &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    info: &MessageInfo,
    msg: M,
    admin: Option<String>,
) -> Result<(Option<Session>, ReturnMsg<M>), AuthError> 
    where M : serde::de::DeserializeOwned + crate::msgs::SessionActionsMatch + Debug,
{

    let session_msg = match msg.match_actions() {
        Some(msg) => msg,
        None => return Ok((None, wrap_one_rmsg(msg))),
    };

    let addr = admin.unwrap_or(info.sender.to_string());
       
    match session_msg {
        SessionActionMsg::CreateSession(
            mut create
        ) => {
            // set sender as granter
            create.session_info.granter = Some(addr);
            let session = create.to_session(&env)?;
            let key = session.key();
            update_session(storage,  &key, &session)?;
            return Ok((Some(session), default_return_msg()));
        },

        SessionActionMsg::CreateSessionFromMsg(
            mut create
        ) => {
            // set sender as granter
            create.session_info.granter = Some(addr);
            let session = create.to_session(&env)?;
            let key = session.key();
            update_session(storage,  &key, &session)?;
            return Ok((Some(session), wrap_one_rmsg(create.message.clone())));
        },

        SessionActionMsg::WithSessionKey(with_msg) => {
            let key = &with_msg.session_key;
            let session = map_get(storage, &SESSIONS, key, "session key")?;
            if session.expiration.is_expired(&env.block) {
                map_remove(storage, &SESSIONS, key);
                return Err(SessionError::Expired.into())
            }
            let msgs   = match with_msg.message {

                ActionMsg::Signed(msg) => {
                    verify_session_signed(api, storage, env, key.as_str(), &session, msg)?
                }
                ActionMsg::Native(execute) => {
                    verify_session_native(api,  addr.as_str(), &session, execute)?
                },
            };
            Ok((Some(session), msgs))
        },

        SessionActionMsg::RevokeSession(msg) => {
            let key = &msg.session_key;
            if let Ok(loaded) = map_get(storage, &SESSIONS, key, "session key") {
                // anyone can revoke the expired session
                if !loaded.expiration.is_expired(&env.block) {
                    ensure!(loaded.granter == addr, SessionError::NotOwner);
                }
                map_remove(storage, &SESSIONS, key);
                Ok((None, default_return_msg()))
            } else {
                return Err(SessionError::NotFound.into())
            }            
        },
    }
    
}



/* pub fn handle_queries<M>(
    storage: &dyn Storage,
    env: &Env,
    info: &MessageInfo,
    msg: M,
) -> Result<Vec<M>, AuthError> 
where M : SessionActionsMatch + DeserializeOwned,
{
    let session_msg = match msg.match_actions() {
        Some(msg) => msg,
        None => return Ok(vec![msg]),
    };
       
    match session_msg {
        SessionActionMsg::QuerySessionKey(msg) => {
            let key = &msg.session_key;
            let session = load_session(storage, key.clone())?;
            ensure!(
                session.granter == info.sender.to_string(), 
                AuthError::Unauthorized("Only owner can revoke the session key".into())
            );
            Ok(vec![session_msg.into()])
        },
        _ => Ok(vec![msg])
    }
}
 */