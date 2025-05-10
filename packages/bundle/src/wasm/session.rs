use core::{fmt::Display, ops::Deref};
use saa_common::{ensure, types::expiration::Expiration, wasm::Env, SessionError};

use serde::Serialize;
use strum::IntoDiscriminant;

use crate::messages::{Action, AllowedActions, CreateSession, CreateSessionFromMsg, GranteeInfo, SessionInfo, SessionKey};


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
                if let AllowedActions::List(ref actions) = actions {
                    ensure!(actions.len() > 0, SessionError::EmptyActions);

                    let no_empties = actions.iter()
                        .all(|action| !action.result.is_empty());

                    let no_dublicaes = actions
                        .iter()
                        .all(|action| {
                            let mut count = 0;
                            for action2 in actions.iter() {
                                if action.method == action2.method && action.result == action2.result {
                                    count += 1;
                                }
                            }
                            count <= 1
                        });

                    ensure!(no_empties && no_dublicaes, SessionError::InvalidActions);
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
    <M::Target as IntoDiscriminant>::Discriminant: ToString,
{
    pub fn to_session_key(
        &self, 
        env: &Env
    ) -> Result<SessionKey, SessionError> {
        let (grantee, expiration, _) = self.session_info.checked_params(env, None)?;
        let action = Action::new(
            self.message.deref(), 
            self.derivation_method.clone().unwrap_or_default()
        )?;
        Ok(SessionKey {
            actions: AllowedActions::List(vec![action]),
            expiration,
            grantee,
            granter: self.session_info.granter.clone(),
        })
    }
}
