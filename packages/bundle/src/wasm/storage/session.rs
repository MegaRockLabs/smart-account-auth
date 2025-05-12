use saa_common::wasm::{Api, MessageInfo, StdError, Storage};
use saa_common::{from_json, AuthError};
use saa_common::{ensure, types::expiration::Expiration, wasm::Env, CredentialId, SessionError};
use serde::de::DeserializeOwned;
use crate::messages::{is_session_action_name, Action, ActionMsg, AllowedActions, CreateSession, CreateSessionFromMsg, DerivableMsg, DerivationMethod, GranteeInfo, MsgDataToSign, Session, SessionActionMsg, SessionInfo};
use crate::traits::SessionActionsMatch;
use crate::utils::construct_credential;
use crate::CredentialName;

use super::stores::SESSIONS;


impl SessionInfo {
    pub(crate) fn checked_params(
        &self, 
        env: &Env,
        actions: Option<&AllowedActions>
    ) -> Result<(CredentialId, GranteeInfo, Expiration, AllowedActions), SessionError> {
        let granter = self.granter.clone().unwrap_or_default();
        //ensure!(!granter.is_empty(), SessionError::InvalidGranter);
        let (id, info) = self.grantee.clone();
        ensure!(!id.is_empty(), SessionError::InvalidGrantee);
        let expiration = self.expiration.unwrap_or_default();
        ensure!(!expiration.is_expired(&env.block), SessionError::Expired);
        if let Some(granter) = &self.granter {
            ensure!(!granter.is_empty() && *granter != id, SessionError::InvalidGranter);
        }
        let actions = match actions {
            Some(actions) => {
                if let AllowedActions::Include(ref actions) = actions {
                    ensure!(actions.len() > 0, SessionError::EmptyCreateActions);

                    let validity_ok = actions
                        .iter()
                        .enumerate()
                        .all(|(i, action)| {
                            let ok = !action.result.is_empty() 
                                &&  actions
                                    .into_iter()
                                    .skip(i + 1)
                                    .filter(|action2| action == *action2)
                                    .count() == 0;
                            ok
                        });
                    ensure!(validity_ok, SessionError::InvalidActions);

                    let no_inner_sessions = actions
                        .iter()
                        .all(|action| {
                            match action.method {
                                // it's okay to generate identical session messages
                                DerivationMethod::Json => !action.result.contains("\"session_actions\"") &&
                                                            !action.result.contains("\"session_info\""),
                                // works well for names and better than nothing for strum strings
                                _ => !is_session_action_name(action.result.as_str())
                                
                            }
                        });
                    ensure!(no_inner_sessions, SessionError::InnerSessionAction);
                }
                actions.clone()
            },
            None => AllowedActions::All {},
        };
        Ok((granter, (id, info), expiration, actions))
    }
}



impl CreateSession {
    pub fn to_session(
        &self, 
        env: &Env
    ) -> Result<Session, SessionError> {
        
        let (
            granter,
            grantee, 
            expiration, 
            actions
        ) = self.session_info.checked_params(env, Some(&self.allowed_actions))?;


        Ok(Session {
            actions,
            expiration,
            grantee,
            granter,
            nonce: 0,
        })
    }
}



impl<M: DerivableMsg> CreateSessionFromMsg<M> {

    pub fn to_session(
        &self, 
        env: &Env
    ) -> Result<Session, SessionError> {
        let (
            granter, 
            grantee, 
            expiration, 
            _
        ) = self.session_info.checked_params(env, None)?;
        
        let method = self.derivation_method.clone().unwrap_or_default();
        let action = Action::new(&self.message, method)?;

        Ok(Session {
            actions: AllowedActions::Include(vec![action]),
            expiration,
            grantee,
            granter,
            nonce: 0,
        })
    }
}






pub fn save_session(
    storage: &mut dyn Storage,
    key: String,
    mut session: Session,
) -> Result<(), StdError> {
    if let Ok(loaded) = load_session(storage, key.clone()) {
        session.nonce = loaded.nonce;
    }
    SESSIONS.save(storage, key, &session)?;
    Ok(())
}



pub fn load_session(
    storage: &dyn Storage,
    key: String
) -> Result<Session, StdError> {
    SESSIONS.load(storage, key)
}


pub fn revoke_session(
    storage: &mut dyn Storage,
    key: String
) -> () {
    SESSIONS.remove(storage, key);
}





pub fn handle_actions<M>(
    api : &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    info: &MessageInfo,
    msg: M,
) -> Result<(Option<Session>, Vec<M>), AuthError> 
    where M : DeserializeOwned + SessionActionsMatch,
{
    let session_msg = match msg.match_actions() {
        Some(msg) => msg,
        None => return Ok((None, vec![msg])),
    };
       
    match session_msg {
        SessionActionMsg::CreateSession(
            mut create
        ) => {
            // set sender as granter
            create.session_info.granter = Some(info.sender.to_string());
            let session = create.to_session(&env).unwrap();
            let key = session.key();
            save_session(storage,  key.clone(), session.clone())?;
            Ok((Some(session), vec![]))
        },

        SessionActionMsg::CreateSessionFromMsg(
            mut create
        ) => {
            // set sender as granter
            create.session_info.granter = Some(info.sender.to_string());
            let session = create.to_session(&env).unwrap();
            let key = session.key();
            save_session(storage,  key.clone(), session.clone())?;
            Ok((Some(session), vec![create.message.clone()]))
        },

        SessionActionMsg::WithSessionKey(with_msg) => {

            let key = &with_msg.session_key;
            let mut session = load_session(storage, key.clone())?;
            let (id, cred_info) = session.grantee.clone();

            if session.expiration.is_expired(&env.block) {
                revoke_session(storage, key.clone());
                return Err(SessionError::Expired.into())
            }

            let msgs : Vec<M>  = match with_msg.message {
                ActionMsg::Signed(msg) => {
                    let stored_ext = cred_info.extension.clone();
                    let (hrp, ext) = match msg.payload {
                        Some(p) => (p.hrp, p.extension),
                        None => (None, None)
                    };
                    let cred = construct_credential(
                        id, 
                        cred_info.name, 
                        msg.data.clone(), 
                        msg.signature, 
                        hrp, 
                        stored_ext, 
                        ext
                    )?;

                    cred.verify_cosmwasm(api)?;

                    let to_sign : MsgDataToSign<M> = from_json(msg.data)?;
                    to_sign.check_fields(env)?;
                    ensure!(session.nonce.to_string() == to_sign.nonce, AuthError::DifferentNonce);
                    
                    session.nonce += 1;
                    save_session(storage, key.clone(), session.clone())?;
                    
                    to_sign.messages
                }
                ActionMsg::Native(execute) => {
                    ensure!(
                        cred_info.name == CredentialName::Native && id == info.sender.to_string(),
                        AuthError::Unauthorized(String::from("This key wasn't for this address"))
                    );
                    vec![execute.clone()]
                },
            };
            ensure!(!msgs.is_empty(), SessionError::EmptyPassedActions);
            ensure!(msgs.iter().all(|m| session.actions.is_message_allowed(m)), SessionError::NotAllowedAction);
            Ok((Some(session), msgs))
        },

        SessionActionMsg::RevokeSession(msg) => {
            let key = &msg.session_key;
            if let Ok(loaded) = load_session(storage, key.clone()) {
                ensure!(
                    loaded.granter == info.sender.to_string(), 
                    AuthError::Unauthorized("Only owner can revoke the session key".into())
                );
                revoke_session(storage, key.clone());
                Ok((None, vec![]))
            } else {
                return Err(SessionError::Expired.into())
            }            
        },
    }
    
}



pub fn handle_queries<M>(
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
