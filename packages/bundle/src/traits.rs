#[cfg(feature = "session")]
pub use crate::messages::actions::DerivableMsg;
#[cfg(feature = "replay")]
pub use saa_crypto::ReplayProtection;
#[cfg(any(feature = "wasm", feature = "native"))]
use crate::data::VerifiedData;

pub use saa_common::{Verifiable, Identifiable};
#[cfg(all(any(feature = "native", feature = "wasm"), feature = "replay"))]
use saa_crypto::ReplayParams;
pub use super::wrapper::CredentialsWrapper;

use crate::{Credential, CredentialData};

#[cfg(feature = "wasm")]
use saa_common::wasm::{Env, MessageInfo, Deps};
use saa_common::AuthError;




impl crate::CredentialsWrapper for CredentialData {
    type Credential = Credential;

    fn credentials(&self) -> &Vec<Self::Credential> {
        &self.credentials
    }

    fn primary_index(&self) -> Option<usize> {
        self.primary_index.clone()
    }
    
    fn validate(&self, sender: impl AsRef<str> )-> Result<(), AuthError> {
        self.validate_logic(sender.as_ref(), None)?;
        self.credentials.iter().try_for_each(|c| c.validate())
    }
    
    #[allow(unused_variables)]
    #[cfg(any(feature = "native", feature = "wasm"))]
    fn verify(&self,
        #[cfg(feature = "wasm")]
        deps: Deps, env: &Env, info: &MessageInfo,
        #[cfg(not(feature = "wasm"))]
        sender: String,
        #[cfg(feature = "replay")]
        params: ReplayParams
    ) -> Result<crate::VerifiedData, AuthError> {
        #[cfg(feature = "wasm")]
        let sender = info.sender.clone();
        let mut pre_val = self.pre_validate.unwrap_or_default();
        let override_primary = self.override_primary.unwrap_or_default();
        let data = self.with_native(sender.as_str());
        let len = data.credentials.len();

        if pre_val || len <= 1 { 
            data.validate(sender.as_ref())?; 
            #[cfg(feature = "replay")]
             self.credentials()
                .into_iter()
                .try_for_each(|c| c.protect_reply(
                    #[cfg(feature = "wasm")]
                    env, 
                    params.clone()
                ))?;
            pre_val = true;
        }

        let mut credentials = Vec::with_capacity(len);
        let mut addresses  = Vec::with_capacity(len);
        let mut has_natives = false;
        let mut has_extensions = false;

        data.credentials
            .clone()
            .into_iter()
            .try_for_each(|c| 
        {
            // if not pre-validated, validating each one by one
            if !pre_val { 
                c.validate()?; 
                #[cfg(feature = "replay")]
                c.protect_reply(
                    #[cfg(feature = "wasm")]
                    env, 
                    params.clone()
                )?;
            }
            // verify siganture and get extracted info like address, name, etc.
            let info = c.verify(
                #[cfg(feature = "wasm")]
                deps
            )?;
            has_extensions |= info.extension.is_some();
            has_natives |= info.name == saa_common::CredentialName::Native;

            if let Some(address) = info.address.clone() {
                addresses.push(address);
            }
            credentials.push((c.cred_id().to_lowercase(), info));
            Ok::<(), AuthError>(())
        })?;

        // running a post check in any scenario
        data.validate_logic(sender.as_str(), Some(&credentials))?;
    
        Ok(VerifiedData {
            primary_id: data.primary_id().to_lowercase(),
            credentials,
            addresses,
            has_natives,
            has_extensions,
            override_primary,
            #[cfg(feature = "replay")]
            nonce: params.nonce + 1,
        })
    }



}
