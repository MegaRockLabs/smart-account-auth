use core::fmt::Display;
use strum::{IntoDiscriminant};
use saa_common::{AuthError, SessionError, FromStr, ToString, ensure};
use super::actions::{Action, ActionDerivation, AllowedActions, DerivableMsg};



impl Display for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.result)
    }
}


impl FromStr for Action {
    type Err = AuthError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Action {
            result: s.to_string(),
            method: ActionDerivation::Name
        })
    }
}


// a list e.g. Vec of Impl FromStr
impl<A : ToString> From<Vec<A>> for AllowedActions {
    fn from(actions: Vec<A>) -> Self {
        if actions.is_empty() {
            return AllowedActions::All {};
        } else {
            AllowedActions::Include(actions.into_iter()
                .map(|action| {
                    let result = action.to_string();
                    Action {
                        result,
                        method: ActionDerivation::Name
                    }
                })
                .collect())
        }
    }
}





#[cfg(feature = "wasm")]
impl<M> DerivableMsg for M
where
    M : IntoDiscriminant + Display + serde::Serialize + Clone,
    <M as IntoDiscriminant>::Discriminant : ToString + AsRef<str>,
{
    fn name(&self) -> String {
        self.discriminant().to_string()
    }

    fn to_json_string(&self) -> Result<String, AuthError> {
        saa_common::to_json_string(self)
            .map_err(|_| AuthError::generic("Failed to convert to JSON string"))
    }
}



#[cfg(not(feature = "wasm"))]
impl<M> DerivableMsg for M
where
    M : IntoDiscriminant<Discriminant : ToString + AsRef<str>> + Display + Clone
{
    fn name(&self) -> String {
        self.discriminant().to_string()
    }
}




fn is_session_action(name: &str) -> bool {
    name.is_empty() || name.contains("session_actions") || name.contains("session_info")
}





impl Action {

    #[cfg(not(feature = "wasm"))]
    pub fn new<M : DerivableMsg>(message: &M, method: ActionDerivation) -> Result<Self, SessionError> {
        let name = message.discriminant().to_string();
        ensure!(!is_session_action(name.as_str()), SessionError::InnerSessionAction);
        let action = match method {
            ActionDerivation::Name => Self {
                method: ActionDerivation::Name,
                result: message.discriminant().to_string(),
            },
            ActionDerivation::String => Self {
                method: ActionDerivation::String,
                result: message.to_string(),
            },
        };
        ensure!(!action.result.is_empty(), SessionError::InvalidActions);
        Ok(action)
    }

    #[cfg(feature = "wasm")]
    pub fn new<M : DerivableMsg>(message: &M, method: ActionDerivation) -> Result<Self, SessionError> {

        let name = message.discriminant().to_string();
        ensure!(!is_session_action(name.as_str()), SessionError::InnerSessionAction);
        let action = match method {
            ActionDerivation::Name => Self {
                method: ActionDerivation::Name,
                result: message.discriminant().to_string(),
            },
            ActionDerivation::String => Self {
                method: ActionDerivation::String,
                result: message.to_string(),
            },
            ActionDerivation::Json => Self {
                method: ActionDerivation::Json,
                result: saa_common::to_json_string(message)
                    .map_err(|_| SessionError::DerivationError)?,
            },
        };
        ensure!(!action.result.is_empty(), SessionError::InvalidActions);
        Ok(action)
        
    }

    #[cfg(feature = "utils")]
    pub fn with_str<A : core::fmt::Display>(message: A) -> Self {
        Self {
            method: ActionDerivation::String,
            result: message.to_string()
        }
    }

    #[cfg(feature = "utils")]
    pub fn with_strum_name<A>(message: A) -> Self  
        where A: IntoDiscriminant<Discriminant : ToString>,
    {
        Self {
            method: ActionDerivation::Name,
            result: message.discriminant().to_string()
        }
    }

    #[cfg(all(feature = "wasm", feature = "utils"))]
    pub fn with_serde_name<A : serde::Serialize>(message: A) -> Result<Self, SessionError> {
        Ok(Self {
            method: ActionDerivation::Name,
            result: serde_json::to_value(message)
                    .map_err(|_| SessionError::DerivationError)?
                    .as_object()
                    .map(|obj| obj.keys()
                        .next()
                        .map(|k| k.to_string())
                    )
                    .flatten()
                    .ok_or(SessionError::DerivationError)?
        })
    }

    #[cfg(all(feature = "wasm", feature = "utils"))]
    pub fn with_serde_json<A : serde::Serialize>(message: A) -> Result<Self, SessionError> {
        Ok(Self {
            method: ActionDerivation::Json,
            result: saa_common::to_json_string(&message)
                    .map_err(|_| SessionError::DerivationError)?
        })
        
    }
}


impl AllowedActions {

    pub fn can_do_action(&self, act: &Action) -> bool {
        if is_session_action(act.result.as_str()) {
            return false;
        }
        match self {
            AllowedActions::All {} => true,
            AllowedActions::Include(ref actions) => actions
                .iter()
                .any(|action| action == act)
        }
    }

    pub fn can_do_msg<M : DerivableMsg>(&self, message: &M) -> bool {
        if is_session_action(message.name().as_str()) {
            return false;
        }
        match self {
            AllowedActions::All {} => true,
            AllowedActions::Include(ref actions) => actions
                .iter()
                .any(|allowed| 
                    if let Ok(derived) = Action::new(message, allowed.method.clone()) {
                        allowed.result == derived.result
                    } else {
                        false
                    }
                )
        }
    }
}








#[cfg(feature = "utils")]
impl AllowedActions {


    pub fn can_do_str<S: saa_common::ToString>(&self, msg: &S) -> bool {
        match self {
            AllowedActions::All {} => true,
            AllowedActions::Include(ref actions) => actions
                .iter()
                .any(|action| 
                    action.method == ActionDerivation::String && 
                    action.result == msg.to_string()
                )
        }
    }

    #[cfg(feature = "wasm")]
    pub fn can_do_json<M : serde::Serialize>(&self, msg: &M) -> bool {
        match self {
            AllowedActions::All {} => true,
            AllowedActions::Include(ref actions) => actions
                .iter()
                .any(|action| {
                    if action.method != ActionDerivation::Json {
                        return false;
                    }
                    let res = Action::with_serde_json(msg)
                        .map(|msg| msg.result)
                        .unwrap_or_default();
                    action.result == res
                })
        }
      
    }

}









#[cfg(all(feature = "wasm", feature = "session"))]
impl super::sessions::SessionInfo {
    pub fn checked_params(
        &self, 
        env: &saa_common::wasm::Env,
        actions: Option<&AllowedActions>
    ) -> Result<(crate::CredentialId, crate::CredentialRecord, crate::Expiration, AllowedActions), SessionError> {
        use saa_common::ensure;
        let granter = self.granter.clone().unwrap_or_default();
        let (id, info) = self.grantee.clone();
        ensure!(!id.is_empty(), SessionError::InvalidGrantee);
        let expiration = self.expiration.clone().unwrap_or_default();
        ensure!(!expiration.is_expired(&env.block), SessionError::Expired);
        if let Some(granter) = &self.granter {
            ensure!(!granter.is_empty() && *granter != id, SessionError::InvalidGranter);
        }
        let actions : AllowedActions = match actions {
            Some(actions) => {
                if let AllowedActions::Include(ref actions) = actions {
                    ensure!(actions.len() > 0, SessionError::EmptyCreateActions);
                    actions
                        .iter()
                        .enumerate()
                        .try_for_each(|(i, action)| {
                            ensure!(
                                !action.result.is_empty()  && actions
                                    .into_iter()
                                    .skip(i + 1)
                                    .filter(|action2| action == *action2)
                                    .count() == 0,
                                SessionError::InvalidActions
                            );
                            ensure!(
                                !is_session_action(action.result.as_str()),
                                SessionError::InnerSessionAction
                            );
                            Ok(())
                        })?;
                }
                actions.clone()
            },
            None => AllowedActions::All {},
        };
        Ok((granter, (id, info), expiration, actions))
    }
}


