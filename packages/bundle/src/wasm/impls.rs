use crate::{msgs::SignedDataMsg,
    credential::{Credential, CredentialInfo, CredentialName}
};
use saa_common::{wasm::{Addr, Api, CustomMsg}, AuthError, CredentialId};

#[cfg(feature = "storage")]
use {
    saa_common::{wasm::{Env, Storage}, Verifiable},
    crate::wasm::storage::stores::{HAS_NATIVES, VERIFYING_ID},
};

#[cfg(feature = "replay")]
use {
    saa_common::{ensure, ReplayError},
    super::storage::{stores::ACCOUNT_NUMBER, replay::account_number},
    crate::msgs::{MsgDataToSign, MsgDataToVerify},
    crate::messages::utils::convert_validate,
};
#[cfg(feature = "session")]
use crate::{
    messages::utils::is_session_action_name,
    messages::actions::{DerivationMethod, DerivableMsg, AllowedActions, Action},
    sessions::actions::{CreateSession, CreateSessionFromMsg},
    sessions::{Session, SessionInfo},
    SessionError, Expiration, CredentialRecord,
};


// Allow usage of `CosmosMsg<SignedDataMsg>` in CosmWasm contracts
impl CustomMsg for SignedDataMsg {}


impl Credential {

    pub fn is_cosmos_derivable(&self) -> bool {
        #[allow(unused_mut)]
        let mut ok = self.hrp().is_some();
        #[cfg(feature = "cosmos")]
        {
            ok = ok && self.name() == CredentialName::CosmosArbitrary;
        }
        ok
    }

    pub fn cosmos_address(&self, api: &dyn Api) -> Result<Addr, AuthError> {
        use saa_common::utils::*;
        let id = self.id();
        let name = self.name();
        if name == CredentialName::Native {
            let addr = api.addr_validate(&id)?;
            return Ok(addr)
        }
        #[cfg(all(feature = "injective", feature="ethereum"))]
        {
            if name == CredentialName::EthPersonalSign {
                return Ok(Addr::unchecked(
                    pubkey_to_address(
                        id.as_bytes(), "inj"
                    )?
                ))
            } 
        }
        Ok(match self.hrp() {
            Some(hrp) => Addr::unchecked(
                pubkey_to_address(id.as_bytes(), &hrp)?
            ),
            None => {
                let canon = pubkey_to_canonical(id.as_bytes());
                let addr = api.addr_humanize(&canon)?;
                addr
            }
        })
    }

}



impl CredentialInfo {
    

    pub fn cosmos_address(&self, api: &dyn Api, id: CredentialId) -> Result<Addr, crate::AuthError> {
        use saa_common::utils::*;
        let name = self.name.clone();
        if name == CredentialName::Native {
            let addr = api.addr_validate(&id)?;
            return Ok(addr)
        }
        #[cfg(all(feature = "injective", feature="ethereum"))]
        {
            if name == CredentialName::EthPersonalSign {
                return Ok(Addr::unchecked(
                    pubkey_to_address(
                        id.as_bytes(), "inj"
                    )?
                ))
            } 
        }
        Ok(match &self.hrp {
            Some(hrp) => Addr::unchecked(
                pubkey_to_address(id.as_bytes(), &hrp)?
            ),
            None => {
                let canon = pubkey_to_canonical(
                    id.as_bytes()
                );
                let addr = api.addr_humanize(&canon)?;
                addr
            }
        })
    }
}







#[cfg(all(feature = "traits", feature = "storage"))]
use crate::traits::CredentialsWrapper;



#[allow(unused_variables)]
#[cfg(feature = "storage")]
impl crate::CredentialData {
    pub fn save(
        &self, 
        api: &dyn Api, 
        store: &mut dyn Storage,
        env: &Env, 
    ) -> Result<Self, AuthError> {
        use crate::wasm::storage::stores::{
            CREDENTIAL_INFOS as INFOS,
            map_save, 
        };
        self.validate()?;
        #[cfg(feature = "replay")]
        {
            self.validate_replay_all(store, env)?;
            ACCOUNT_NUMBER.save(store, &1u64)?;
        }
        let mut has_natives = false;
        for cred in self.credentials.iter() {
            cred.verify_cosmwasm(api)?;

            let info = cred.info();
            if info.name == CredentialName::Native { 
                has_natives = true 
            }
            map_save(store, &INFOS, &cred.id(),&info, "new credential")?;
        }
        HAS_NATIVES.save(store, &has_natives)?;
        #[cfg(feature = "traits")]
        let id: String = self.primary_id();
        #[cfg(not(feature = "traits"))]
        let id = self.credentials.first().unwrap().id();
        VERIFYING_ID.save(store, &id)?;
        Ok(self.clone())
    }


}





#[cfg(feature = "replay")]
impl crate::CredentialData {
    pub fn validate_replay_all(
        &self, 
        storage: &dyn Storage, 
        env: &Env,
    ) -> Result<(), AuthError> {
        
        let credentials : Vec<&crate::credential::Credential> = self.credentials
            .iter().filter(|c| 
                c.name() != crate::credential::CredentialName::Native 
                //&& !c.message().is_empty()
            )
            .collect();

        if credentials.is_empty() { return Ok(()) }
     
        let nonce = account_number(storage);
        
        credentials
            .into_iter()
            .try_for_each(|c| convert_validate(c.message(), env, nonce))?;
                
        Ok(())
    }
}



#[cfg(feature = "replay")]
impl MsgDataToVerify {
    pub fn validate(&self, env: &Env, expected: u64 ) -> Result<(), ReplayError> {
        ensure!(self.chain_id == env.block.chain_id, ReplayError::ChainIdMismatch);
        ensure!(self.contract_address == env.contract.address.to_string(), ReplayError::ContractMismatch);
        let signed = self.nonce.u64();
        ensure!(signed == expected, ReplayError::DifferentNonce(signed, expected));
        Ok(())
    }
}


#[cfg(feature = "replay")]
impl<M : serde::de::DeserializeOwned> MsgDataToSign<M> {
    pub fn validate(&self, env: &Env, nonce: u64) -> Result<(), ReplayError> {
        Into::<MsgDataToVerify>::into(self).validate(env, nonce)
    }
}





#[cfg(feature = "session")]
impl SessionInfo {
    pub(crate) fn checked_params(
        &self, 
        env: &Env,
        actions: Option<&AllowedActions>
    ) -> Result<(CredentialId, CredentialRecord, Expiration, AllowedActions), SessionError> {
        use saa_common::ensure;
        let granter = self.granter.clone().unwrap_or_default();
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
                                #[cfg(feature = "wasm")]
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



#[cfg(feature = "session")]
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
            #[cfg(feature = "replay")]
            nonce: 0,
        })
    }
}


#[cfg(feature = "session")]
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
        
        let method = self.derivation.clone().unwrap_or_default();
        let action = Action::new(&self.message, method)?;

        Ok(Session {
            actions: AllowedActions::Include(vec![action]),
            expiration,
            grantee,
            granter,
            #[cfg(feature = "replay")]
            nonce: 0,
        })
    }
}

