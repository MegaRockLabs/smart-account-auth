#[cfg(any(feature = "wasm", feature = "native"))]
use crate::data::VerifiedData;
#[cfg(feature = "session")]
pub use crate::messages::actions::DerivableMsg;
#[cfg(feature = "replay")]
pub use saa_crypto::ReplayProtection;
pub use saa_common::{Verifiable, Identifiable};
pub use super::wrapper::CredentialsWrapper;


#[cfg(feature = "wasm")]
use saa_common::wasm::{Env, MessageInfo, Deps};
use crate::{Credential, CredentialName, CredentialAddress, CredentialData};
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


    #[cfg(all(any(feature = "native", feature = "wasm"), feature = "replay"))]
    fn verify<M>(&self,
        #[cfg(feature = "wasm")]
        deps: Deps, env: &Env, info: &MessageInfo,
        messages: Vec<M>,
    ) -> Result<VerifiedData, AuthError>
    where M: serde::Serialize + Clone {
        #[cfg(feature = "wasm")]
        let sender = info.sender.clone();
        let pre_val = self.pre_validate.unwrap_or_default();

        // validate the wrapper and each credential individually before-hand
        if pre_val { self.validate(sender.as_ref())?; }

        let use_native = self.use_native.unwrap_or_default();
        // flags describing the cred data batch 
        let mut has_natives = false;
        let mut has_extensions = false;

        // can be set by both client or verifying environment
        let nonce = self.nonce.unwrap_or(saa_common::Uint64::zero());

        // each non-native credential must have message to be equal to this envelope
        let binary_envelope  = crate::msgs::MsgDataToSign::new_binary(env, nonce.clone(), messages)?;
                
        // ID + Parsed Info
        let mut credentials = Vec::with_capacity(self.credentials.len() + 1);
        // Parsed Addresses
        let mut addresses  = Vec::with_capacity(self.credentials.len() + 1);

        self.credentials
            .iter()
            .try_for_each(|c| {
                // if not pre-validated, validating each one by one
                if !pre_val { c.validate()?; }

                // verify siganture and get extracted info like address, name, etc.
                let info = c.verify(
                    #[cfg(feature = "wasm")]
                    deps
                )?;
                has_extensions |= info.extension.is_some();
                if info.name != CredentialName::Native {
                    saa_common::ensure!(
                        c.message() == binary_envelope.as_slice(),  
                        saa_common::ReplayError::InvalidEnvelope
                    );
                } else {
                    has_natives = true;
                }
                if let Some(address) = info.address.clone() {
                    addresses.push(address);
                }
                credentials.push((c.id(), info));
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
            verifying_id: self.primary_id(),
            override_ver: self.override_primary.unwrap_or_default(),
            nonce: nonce.u64() + 1,
        })
    }


    #[cfg(all(any(feature = "native", feature = "wasm"), not(feature = "replay")))]
    fn verify(&self,
        #[cfg(feature = "wasm")]
        deps: Deps, _env: &Env, info: &MessageInfo,
    ) -> Result<crate::data::VerifiedData, AuthError> {
        #[cfg(feature = "wasm")]
        let sender = info.sender.clone();
        let pre_val = self.pre_validate.unwrap_or_default();
        if pre_val { self.validate(sender.as_ref())?; }

        let use_native = self.use_native.unwrap_or_default();
        let mut has_natives = false;
        let mut has_extensions = false;
        let mut credentials = Vec::with_capacity(self.credentials.len() + 1);
        let mut addresses  = Vec::with_capacity(self.credentials.len() + 1);

        self.credentials
            .iter()
            .try_for_each(|c| {
                // if not pre-validated, validating each one by one
                if !pre_val { c.validate()?; }
                // verify siganture and get extracted info like address, name, etc.
                let info = c.verify(
                    #[cfg(feature = "wasm")]
                    deps
                )?;
                has_natives |= info.name == CredentialName::Native;
                has_extensions |= info.extension.is_some();
                if let Some(address) = info.address.clone() {
                    addresses.push(address);
                }
                credentials.push((c.id(), info));
                Ok::<(), AuthError>(())
                }
            )?;

        if use_native && !has_natives {
            addresses.push(CredentialAddress::Bech32(sender.clone()));
            credentials.push((sender.to_string(), sender.clone().into()));
        }

        self.validate_logic(sender.as_str(), Some(&credentials))?;
        
        Ok(VerifiedData {
            credentials,
            addresses,
            has_natives,
            has_extensions,
            verifying_id: self.primary_id(),
            override_ver: self.override_primary.unwrap_or_default(),
        })

    }

    
}
