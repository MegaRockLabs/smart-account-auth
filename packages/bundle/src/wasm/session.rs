use core::{fmt::Display, ops::Deref};
use saa_common::{ensure, types::expiration::Expiration, wasm::Env, SessionError};

use serde::Serialize;
use strum::IntoDiscriminant;

use crate::messages::{is_session_action_name, Action, AllowedActions, CreateSession, CreateSessionFromMsg, DerivationMethod, GranteeInfo, SessionInfo, SessionKey};


impl SessionInfo {
    pub(crate) fn checked_params(
        &self, 
        env: &Env,
        actions: Option<&AllowedActions>
    ) -> Result<(GranteeInfo, Expiration, AllowedActions), SessionError> {
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
                    ensure!(actions.len() > 0, SessionError::EmptyActions);

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
                                DerivationMethod::Json => !action.result.contains("\"session_info\""),
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
        Ok(((id, info), expiration, actions))
    }
}



impl CreateSession {
    pub fn to_session_key(
        &self, 
        env: &Env
    ) -> Result<SessionKey, SessionError> {
        let (
            grantee, 
            expiration, 
            actions
        ) = self.session_info.checked_params(env, Some(&self.allowed_actions))?;

        Ok(SessionKey {
            actions,
            expiration,
            grantee,
            granter: self.session_info.granter.clone(),
        })
    }
}



impl<M> CreateSessionFromMsg<M> 
where
    M: Deref,
    M::Target: IntoDiscriminant + Display + Serialize + Clone,
    <M::Target as IntoDiscriminant>::Discriminant: AsRef<str> + ToString,
{
    pub fn to_session_key(
        &self, 
        env: &Env
    ) -> Result<SessionKey, SessionError> {
        let (grantee, expiration, _) = self.session_info.checked_params(env, None)?;
        
        let msg = self.message.deref();
       
        
        let method = self.derivation_method.clone().unwrap_or_default();
        let action = Action::new(msg, method)?;
        ensure!(!action.result.is_empty(), SessionError::InvalidActions);

        Ok(SessionKey {
            actions: AllowedActions::Include(vec![action]),
            expiration,
            grantee,
            granter: self.session_info.granter.clone(),
        })
    }
}
