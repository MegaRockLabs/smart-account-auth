#[cfg(feature = "session")]
pub use crate::messages::actions::DerivableMsg;
#[cfg(feature = "replay")]
pub use {saa_crypto::ReplayProtection, super::wrapper::ReplayProtectionWrapper};
#[cfg(any(feature = "wasm", feature = "native"))]
use crate::data::VerifiedData;

pub use saa_common::{Verifiable, Identifiable};
#[cfg(all(any(feature = "native", feature = "wasm"), feature = "replay"))]
use saa_crypto::ReplayParams;
pub use super::wrapper::CredentialsWrapper;

use crate::{Credential, CredentialName, CredentialAddress, CredentialData};

#[cfg(feature = "wasm")]
use saa_common::wasm::{Env, MessageInfo, Deps};
use saa_common::AuthError;





/* 
pub trait Identifiable : Verifiable + strum::IntoDiscriminant<Discriminant : core::fmt::Display> {

    fn name(&self) -> <Self as IntoDiscriminant>::Discriminant {
        self.discriminant()    
    }

    fn extension(&self) -> Option<saa_common::InfoExtension>;    

}
 */



/* impl Identifiable for Credential {
    
   /*  fn extension(&self) -> Option<InfoExtension> {
        #[cfg(feature = "passkeys")]
        if let Credential::Passkey(c) = self {
            return Some(c.clone().into())
        }
        None
    } */

}

 */



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
        #[cfg(all(feature = "replay", feature = "optimise"))]
        params: ReplayParams,
        #[cfg(all(feature = "replay", not(feature = "optimise")))]
        params: ReplayParams<impl serde::Serialize + core::fmt::Display + Clone>
    ) -> Result<crate::VerifiedData, AuthError> {
        #[cfg(feature = "wasm")]
        let sender = info.sender.clone();
        #[cfg(feature = "replay")]
        let nonce = self.nonce.unwrap_or_default().u64();
        let pre_val = self.pre_validate.unwrap_or_default();

        if pre_val { 
            self.validate(sender.as_ref())?; 
            #[cfg(feature = "replay")]
            self.protect_reply(
                #[cfg(feature = "wasm")]
                env,
                #[cfg(feature = "replay")]
                params.clone()
            )?;
        }

        let use_native = self.use_native.unwrap_or_default();
        // flags describing the cred data batch 
        let mut has_natives = false;
        let mut has_extensions = false;

        let mut credentials = Vec::with_capacity(self.credentials.len());
        // Parsed Addresses
        let mut addresses  = Vec::with_capacity(self.credentials.len());

        self.credentials.iter().try_for_each(|c| {
            // if not pre-validated, validating each one by one
            if !pre_val { 
                c.validate()?; 
                println!("Validating credential {:?}", c);
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
            has_natives |= info.name == CredentialName::Native;

            if let Some(address) = info.address.clone() {
                addresses.push(address);
            }
            credentials.push((c.id().to_lowercase(), info));
            Ok::<(), AuthError>(())
        })?;

        if use_native && !has_natives {
            addresses.push(CredentialAddress::Bech32(sender.clone()));
            credentials.push((sender.to_string(), sender.clone().into()));
        }

        // running a post check in any scenario
        self.validate_logic(sender.as_str(), Some(&credentials))?;
    
        Ok(VerifiedData {
            credentials,
            addresses,
            has_natives,
            has_extensions,
            primary_id: self.primary_id().to_lowercase(),
            override_primary: self.override_primary.unwrap_or_default(),
            #[cfg(feature = "replay")]
            nonce: nonce + 1,
        })
    }


/*     #[cfg(all(any(feature = "native", feature = "wasm"), feature = "optimise"))]
    fn verify_t(&self,
        #[cfg(feature = "wasm")]
        deps: Deps, env: &Env, info: &MessageInfo,
        #[cfg(feature = "replay")]
        params: ReplayParams
    ) -> Result<VerifiedData, AuthError>  {
        #[cfg(feature = "wasm")]
        let sender = info.sender.clone();
        #[cfg(feature = "replay")]
        let nonce = self.nonce.unwrap_or_default().u64();
        let pre_val = self.pre_validate.unwrap_or_default();

        if pre_val { 
            self.validate(sender.as_ref())?; 
            self.protect_reply(
                #[cfg(feature = "wasm")]
                env,
                #[cfg(feature = "replay")]
                params.clone()
            )?;
        }

        let use_native = self.use_native.unwrap_or_default();
        // flags describing the cred data batch 
        let mut has_natives = false;
        let mut has_extensions = false;

        let mut credentials = Vec::with_capacity(self.credentials.len());
        // Parsed Addresses
        let mut addresses  = Vec::with_capacity(self.credentials.len());

        self.credentials.iter().try_for_each(|c| {
            // if not pre-validated, validating each one by one
            if !pre_val { 
                c.validate()?; 
                c.protect_reply(
                    #[cfg(feature = "wasm")]
                    env, 
                    #[cfg(feature = "replay")]
                    params.clone()
                )?;
            }
            // verify siganture and get extracted info like address, name, etc.
            let info = c.verify(
                #[cfg(feature = "wasm")]
                deps
            )?;
            has_extensions |= info.extension.is_some();
            has_natives |= info.name == CredentialName::Native;

            if let Some(address) = info.address.clone() {
                addresses.push(address);
            }
            credentials.push((c.id().to_lowercase(), info));
            Ok::<(), AuthError>(())
        })?;

        if use_native && !has_natives {
            addresses.push(CredentialAddress::Bech32(sender.clone()));
            credentials.push((sender.to_string(), sender.clone().into()));
        }

        // running a post check in any scenario
        self.validate_logic(sender.as_str(), Some(&credentials))?;
    
        Ok(VerifiedData {
            credentials,
            addresses,
            has_natives,
            has_extensions,
            primary_id: self.primary_id().to_lowercase(),
            override_primary: self.override_primary.unwrap_or_default(),
            nonce: nonce + 1,
        })
    }
 */



}
