use core::ops::Deref;

use strum::IntoDiscriminant;
use saa_auth::caller::Caller;
use saa_common::{ensure, AuthError, Binary, CredentialId, CredentialInfo, Verifiable};
use crate::{credential::CredentialName, Credential, CredentialData};


impl From<Caller> for Credential {
    fn from(c: Caller) -> Self {
        Credential::Native(c)
    }
}

#[cfg(feature = "ethereum")]
impl From<saa_auth::eth::EthPersonalSign> for Credential {
    fn from(c: saa_auth::eth::EthPersonalSign) -> Self {
        Credential::EthPersonalSign(c)
    }
}

#[cfg(feature = "cosmos")]
impl From<saa_auth::cosmos::CosmosArbitrary> for Credential {
    fn from(c: saa_auth::cosmos::CosmosArbitrary) -> Self {
        Credential::CosmosArbitrary(c)
    }
}


#[cfg(feature = "passkeys")]
impl From<saa_auth::passkey::PasskeyCredential> for Credential {
    fn from(c: saa_auth::passkey::PasskeyCredential) -> Self {
        Credential::Passkey(c)
    }
}

#[cfg(feature = "curves")]
impl From<saa_curves::secp256k1::Secp256k1> for Credential {
    fn from(c: saa_curves::secp256k1::Secp256k1) -> Self {
        Credential::Secp256k1(c)
    }
}

#[cfg(feature = "curves")]
impl From<saa_curves::secp256r1::Secp256r1> for Credential {
    fn from(c: saa_curves::secp256r1::Secp256r1) -> Self {
        Credential::Secp256r1(c)
    }
}


#[cfg(any(feature = "curves", feature = "ed25519"))]
impl From<saa_curves::ed25519::Ed25519> for Credential {
    fn from(c: saa_curves::ed25519::Ed25519) -> Self {
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
            return Ok(Some(saa_common::to_json_binary(&PasskeyExtension {
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




#[cfg(feature = "traits")]
use crate::wrapper::CredentialsWrapper;

#[cfg(feature = "traits")]
impl crate::wrapper::CredentialsWrapper for CredentialData {
    type Credential = Credential;

    fn credentials(&self) -> &Vec<Self::Credential> {
        &self.credentials
    }
}



impl Verifiable for CredentialData {

    fn id(&self) -> CredentialId {
        #[cfg(feature = "traits")]
        return self.primary_id();
        #[cfg(not(feature = "traits"))]
        self.credentials.first().unwrap().id().clone()

    }

    fn validate(&self) -> Result<(), AuthError> {
        let creds = &self.credentials;
        let using_caller = self.use_native.unwrap_or(false);

        let (min_len, max_len) = if using_caller {
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

        if let Some(index) = self.primary_index {
            let len = creds.len() + if using_caller { 1 } else { 0 };
            ensure!((index as usize) < len, AuthError::generic(
                format!("Primary index {} is out of bounds", index)
            ));
        }
        creds.iter().try_for_each(|c| c.validate())
    }


    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.credentials.iter().try_for_each(|c| c.verify())
    }


    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self,  api : &dyn saa_common::wasm::Api) -> Result<(), AuthError>  {
        self.credentials.iter().try_for_each(|c| c.verify_cosmwasm(api))
    }

}





impl CredentialData {

    fn cred_index(&self, name: CredentialName, id: Option<CredentialId>) -> Option<usize> {
        self.credentials.iter()
            .position(|c| c.name() == name && 
                    id.as_ref()
                        .map(|i| c.id() == *i)
                        .unwrap_or(true)
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

        match self.cred_index(CredentialName::Native, Some(caller.id.clone())) {
            Some(index) => credentials[index] = caller.into(),
            None => credentials.push(caller.into())
        };
        Self { 
            credentials, 
            use_native: Some(true),
            primary_index: self.primary_index
        }
    }

    pub fn with_credential(&self, new: Credential) -> Self {
        let mut credentials = self.credentials.clone();
        match self.cred_index(new.name(), Some(new.id())) {
            Some(index) => credentials[index] = new,
            None => credentials.push(new)
        };
        Self { 
            credentials, 
            use_native: self.use_native,
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
