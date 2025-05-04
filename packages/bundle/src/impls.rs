use core::ops::Deref;

use strum::IntoDiscriminant;
use saa_auth::{caller::Caller, cosmos::CosmosArbitrary, eth::EthPersonalSign, passkey::PasskeyCredential};
use saa_common::{ensure, to_json_binary, AuthError, Binary, CredentialId, CredentialInfo, Verifiable};
use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1, secp256r1::Secp256r1};
use crate::{credential::CredentialName, Credential, CredentialData, CredentialsWrapper};


impl From<Caller> for Credential {
    fn from(c: Caller) -> Self {
        Credential::Native(c)
    }
}

#[cfg(feature = "ethereum")]
impl From<EthPersonalSign> for Credential {
    fn from(c: EthPersonalSign) -> Self {
        Credential::EthPersonalSign(c)
    }
}

#[cfg(feature = "cosmos")]
impl From<CosmosArbitrary> for Credential {
    fn from(c: CosmosArbitrary) -> Self {
        Credential::CosmosArbitrary(c)
    }
}


#[cfg(feature = "passkeys")]
impl From<PasskeyCredential> for Credential {
    fn from(c: PasskeyCredential) -> Self {
        Credential::Passkey(c)
    }
}

#[cfg(feature = "curves")]
impl From<Secp256k1> for Credential {
    fn from(c: Secp256k1) -> Self {
        Credential::Secp256k1(c)
    }
}

#[cfg(feature = "curves")]
impl From<Secp256r1> for Credential {
    fn from(c: Secp256r1) -> Self {
        Credential::Secp256r1(c)
    }
}


#[cfg(any(feature = "curves", feature = "ed25519"))]
impl From<Ed25519> for Credential {
    fn from(c: Ed25519) -> Self {
        Credential::Ed25519(c)
    }
}





impl Deref for Credential {
    type Target = dyn Verifiable;

    fn deref(&self) -> &Self::Target {
        match self {
            Credential::Native(c) => c,
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c,
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c,
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c,
            #[cfg(all(not(feature = "curves"), feature = "ed25519"))]
            Credential::Ed25519(c) => c,
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c,
                    Credential::Secp256r1(c) => c,
                    Credential::Ed25519(c) => c,
                    _ => unreachable!(),
                }
            },
        }
    }
}


impl Credential {

    pub fn name(&self) -> CredentialName {
        self.discriminant()
    }

    pub fn value(&self) -> &dyn Verifiable {
        self.deref()
    }

    pub fn message(&self) -> Vec<u8> {
        match self {
            Credential::Native(_) => Vec::new(),
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c.message.to_vec(),
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.message.to_vec(),
            #[cfg(all(not(feature = "curves"), feature = "ed25519"))]
            Credential::Ed25519(c) => c.message.to_vec(),
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c.base64_message_bytes().unwrap(),
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c.message.to_vec(),
                    Credential::Secp256r1(c) => c.message.to_vec(),
                    Credential::Ed25519(c) => c.message.to_vec(),
                    _ => unreachable!(),
                }
            },
            
        }
    }

    pub fn extension(&self) -> Result<Option<Binary>, AuthError> {
        #[cfg(feature = "passkeys")]
        if let Credential::Passkey(c) = self {
            use saa_auth::passkey::*;
            return Ok(Some(to_json_binary(&PasskeyExtension {
                origin: c.client_data.origin.clone(),
                cross_origin: c.client_data.cross_origin.clone(),
                pubkey: c.pubkey.clone(),
                user_handle: c.user_handle.clone(),
            })?));
        }
        Ok(None)
    }

    pub fn info(&self) -> CredentialInfo {
        CredentialInfo {
            name: self.name().to_string(),
            hrp: self.hrp(),
            extension: self.extension().unwrap_or(None),
        }
    }

    
}





impl CredentialsWrapper for CredentialData {
    type Credential = Credential;

    fn credentials(&self) -> &Vec<Self::Credential> {
        &self.credentials
    }
}



impl Verifiable for CredentialData {

    fn id(&self) -> CredentialId {
        self.primary_id()
    }

    fn validate(&self) -> Result<(), AuthError> {
        let creds = self.credentials();
        let with_caller = self.use_native.unwrap_or(false);

        let (min_len, max_len) = if with_caller {
            let count = creds
                .iter()
                .filter(|c| c.discriminant() == CredentialName::Native)
                .count();
            ensure!(count == 1, AuthError::generic("Native caller is set but wasn't passed by environment"));
            (0, 256)
        } else {
            (1, 255)
        };
    
        if creds.len() < min_len {
            return Err(AuthError::NoCredentials);
        } else if creds.len() > max_len {
            return Err(AuthError::Generic(format!("Too many credentials: {}", creds.len())));
        }

        if let Some(index) = self.primary_index() {
            let len = creds.len() + if with_caller { 1 } else { 0 };
            ensure!((index as usize) < len, AuthError::generic(
                format!("Primary index {} is out of bounds", index)
            ));
        }
        creds.iter().try_for_each(|c| c.validate())
    }


    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.credentials().iter().try_for_each(|c| c.verify())
    }


    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self,  api : &dyn saa_common::wasm::Api) -> Result<(), AuthError>  {
        self.credentials().iter().try_for_each(|c| c.verify_cosmwasm(api))
    }

}





impl CredentialData {

    fn caller_index(&self, _new_id: &CredentialId) -> Option<usize> {
        self.credentials.iter()
            .position(|c| 
                c.name() == CredentialName::Native
                // && c.id() == self.caller_id
            )
    }

    /// Check whether with_caller flag is set and then ether ignore the arguemnt and return a copy
    /// or constuct a new wrapper with the credential being set
    /// @param cal: native caller of the environment
    /// @return: checked wrapper and a flag indicating whether the copy deviated from the original Self
    pub fn with_native_caller<C: Into::<Caller>> (&self, cal: C) -> Self {

        if !self.use_native.unwrap_or(false) {
            return self.clone()
        }

        let caller : Caller = cal.into();
        let mut credentials = self.credentials.clone();

        match self.caller_index(&caller.id) {
            Some(index) => credentials[index] = caller.into(),
            None => credentials.push(caller.into())
        };

        Self { 
            credentials, 
            use_native: Some(true),
            primary_index: self.primary_index
        } 
    }


}



#[cfg(test)]
impl Default for CredentialData {
    fn default() -> Self {
        Self {
            use_native: Some(true),
            credentials: vec![],
            primary_index: None,
        }
    }
}
