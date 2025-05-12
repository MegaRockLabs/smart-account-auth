use saa_common::wasm::{StdError, Storage};
use saa_common::{ensure, types::expiration::Expiration, wasm::Env, CredentialId, SessionError};
use crate::messages::{is_session_action_name, Action, AllowedActions, CreateSession, CreateSessionFromMsg, DerivableMsg, DerivationMethod, GranteeInfo, Session, SessionInfo};

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