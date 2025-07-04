#[cfg(feature = "replay")]
use super::traits::ReplayProtection;
use core::ops::Deref;

use saa_common::{CredentialError, Identifiable, ensure};
use crate::{credential::CredentialName, Credential, CredentialData, caller::Caller};
use crate::traits::CredentialsWrapper;


impl From<Caller> for Credential {
    fn from(c: Caller) -> Self {
        Credential::Native(c)
    }
}


impl From<&str> for Credential {
    fn from(s: &str) -> Self {
        Caller::from(s).into()
    }
}


#[cfg(feature = "eth_personal")]
impl From<saa_auth::eth::EthPersonalSign> for Credential {
    fn from(c: saa_auth::eth::EthPersonalSign) -> Self {
        Credential::EthPersonalSign(c)
    }
}

#[cfg(feature = "eth_typed_data")]
impl From<saa_auth::eth::EthTypedData> for Credential {
    fn from(c: saa_auth::eth::EthTypedData) -> Self {
        Credential::EthTypedData(c)
    }
}


#[cfg(any(feature = "cosmos_arb", feature = "cosmos_arb_addr"))]
impl From<saa_auth::cosmos::CosmosArbitrary> for Credential {
    fn from(c: saa_auth::cosmos::CosmosArbitrary) -> Self {
        Credential::CosmosArbitrary(c)
    }
}


#[cfg(feature = "ed25519")]
impl From<saa_curves::ed25519::Ed25519> for Credential {
    fn from(c: saa_curves::ed25519::Ed25519) -> Self {
        Credential::Ed25519(c)
    }
}


#[cfg(feature = "secp256k1")]
impl From<saa_curves::secp256k1::Secp256k1> for Credential {
    fn from(c: saa_curves::secp256k1::Secp256k1) -> Self {
        Credential::Secp256k1(c)
    }
}

#[cfg(feature = "secp256r1")]
impl From<saa_passkeys::Secp256r1> for Credential {
    fn from(c: saa_passkeys::Secp256r1) -> Self {
        Credential::Secp256r1(c)
    }
}


#[cfg(feature = "passkeys")]
impl From<saa_passkeys::PasskeyCredential> for Credential {
    fn from(c: saa_passkeys::PasskeyCredential) -> Self {
        Credential::Passkey(c)
    }
}



impl Identifiable for Credential {
    fn id(&self) -> String {
        self.deref().id()
    }
    fn name(&self) -> CredentialName {
        self.deref().name()
    }
}


impl Deref for Credential {
    #[cfg(not(feature = "replay"))]
    type Target = dyn saa_common::Verifiable;
    #[cfg(feature = "replay")]
    type Target = dyn ReplayProtection;


    fn deref(&self) -> &Self::Target {
        match self {
            Credential::Native(c) => c,
            #[cfg(feature = "eth_personal")]
            Credential::EthPersonalSign(c) => c,
            #[cfg(feature = "eth_typed_data")]
            Credential::EthTypedData(c) => c,
            #[cfg(any(feature = "cosmos_arb", feature = "cosmos_arb_addr"))]
            Credential::CosmosArbitrary(c) => c,
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c,
            #[cfg(feature = "secp256r1")]
            Credential::Secp256r1(c) => c,
            #[cfg(feature = "secp256k1")]
            Credential::Secp256k1(c) => c,
            #[cfg(feature = "ed25519")]
            Credential::Ed25519(c) => c,
        }
    }
}






impl CredentialData {
    /// Pre-validate without params using self.credentials() or post-validate using verified records
    pub(crate) fn validate_logic(
        &self, sender: &str, 
        records: Option<&Vec<crate::credential::CredentialRecord>>
    ) -> Result<(), CredentialError> {
        // self.credentials for pre-validated and parsed recprds for post-validation
        let iter: Box<dyn Iterator<Item = (String, CredentialName)> + '_> = match records {
            Some(
                records
            ) => Box::new(records.iter().map(|(id, info)| (id.clone(), info.name.clone()))),
            None => Box::new(self.credentials.iter().map(|c| (c.id(), c.name()))),
        };
        // count of credentials, native credentials and whether the sender is found
        let (count, native_count, sender_found) = iter.fold(
            (0, 0, false),
            |(count, native_count, sender_found), (id, name)| (
                    count + 1, 
                    if name == CredentialName::Native { native_count + 1 } else { native_count }, 
                    sender_found || id == sender
            )
        );
        ensure!(count > 0, CredentialError::NoCredentials);
        ensure!(count <= 255, CredentialError::TooManyCredentials(count));

        if let Some(index) = self.primary_index {
            ensure!(index < count, CredentialError::IndexOutOfBounds(index, count));
        }
        if self.use_native.unwrap_or_default() {
            ensure!(native_count > 0, CredentialError::NoNativeCaller);
        }
        // if all are native make sure that at least one is a validated by the node / environment
        if native_count == count {
            ensure!(sender_found, CredentialError::OnlyCustomNatives);
        }
        Ok(())
    }
}



impl CredentialData {

    #[cfg(feature = "utils")]
    pub fn new(
        credentials: Vec<Credential>,
        use_native: Option<bool>,
    ) -> Self {
        Self {
            credentials,
            use_native,
            primary_index: None,
            pre_validate: None,
            override_primary: None,
        }
    }

    /// Check whether with_caller flag is set and then ether ignore the arguemnt returning self
    /// or constucting a new wrapper with the Caller credential being injected 
    /// @param cal: native caller of the environment
    /// @return: checked wrapper 
    pub fn with_native<C: Into::<Caller>> (self, cal: C) -> Self {
        if !self.use_native.unwrap_or(false) {
            return self
        }
        let caller : Caller = cal.into();
        let mut credentials = self.credentials.clone();
        match self.cred_index( &caller.0, CredentialName::Native) {
            Some(index) => credentials[index] = caller.into(),
            None => credentials.push(caller.into())
        };
        Self { 
            credentials, 
            ..self
        }
    }


}

