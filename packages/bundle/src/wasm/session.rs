use core::{fmt::Display, ops::Deref};
use saa_common::{ensure, types::expiration::Expiration, wasm::Env, SessionError};

use serde::Serialize;
use strum::IntoDiscriminant;

use crate::messages::{Action, AllowedActions, CreateSession, CreateSessionForMsg, GranteeInfo, SessionInfo, SessionKey};


impl SessionInfo {
    pub(crate) fn checked_params(
        &self, 
        env: &Env,
        check_actions: bool
    ) -> Result<(GranteeInfo, Expiration, AllowedActions), SessionError> {
        let (id, info) = self.grantee.clone();
        ensure!(!id.is_empty(), SessionError::InvalidGrantee);
        let expiration = self.expiration.unwrap_or_default();
        ensure!(!expiration.is_expired(&env.block), SessionError::Expired);
        if let Some(granter) = &self.granter {
            ensure!(!granter.is_empty() && *granter != id, SessionError::InvalidGranter);
        }
        let actions = match self.actions {
            Some(ref actions) => {
                if check_actions {
                    if let AllowedActions::List(ref actions) = actions {
                        ensure!(actions.len() > 0, SessionError::EmptyActions);
                        let all_valid = actions.iter()
                            .all(|action| !action.result.is_empty());
                        ensure!(all_valid, SessionError::InvalidActions(String::from("Passed actions with empty results")));
                    }
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
        ) = self.session_info.checked_params(env, true)?;

        Ok(SessionKey {
            actions,
            expiration,
            grantee,
            granter: self.session_info.granter.clone(),
        })
    }
}



impl<M> CreateSessionForMsg<M> 
where
    M: Deref,
    M::Target: IntoDiscriminant + Display + Serialize + Clone,
    <M::Target as IntoDiscriminant>::Discriminant: ToString,
{
    pub fn to_session_key(
        &self, 
        env: &Env
    ) -> Result<SessionKey, SessionError> {
        let (grantee, expiration, _) = self.session_info.checked_params(env, false)?;
        let action = Action::new(self.message.clone(), self.derivation_method.clone().unwrap_or_default())?;
        
        Ok(SessionKey {
            actions: AllowedActions::List(vec![action]),
            expiration,
            grantee,
            granter: self.session_info.granter.clone(),
        })
    }
}
