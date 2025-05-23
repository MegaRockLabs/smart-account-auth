use core::ops::Deref;
use strum::IntoDiscriminant;
use saa_common::{ensure, AuthError, Binary, CredentialId, Verifiable};
use crate::{credential::CredentialName, Credential, CredentialData, CredentialInfo, caller::Caller};


impl From<Caller> for Credential {
    fn from(c: Caller) -> Self {
        Credential::Native(c)
    }
}

#[cfg(feature = "eth_personal")]
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
impl From<saa_passkeys::secp256r1::Secp256r1> for Credential {
    fn from(c: saa_passkeys::secp256r1::Secp256r1) -> Self {
        Credential::Secp256r1(c)
    }
}


#[cfg(feature = "passkeys")]
impl From<saa_passkeys::passkey::PasskeyCredential> for Credential {
    fn from(c: saa_passkeys::passkey::PasskeyCredential) -> Self {
        Credential::Passkey(c)
    }
}



impl Deref for Credential {
    type Target = dyn Verifiable;

    fn deref(&self) -> &Self::Target {
        match self {
            Credential::Native(c) => c,
            #[cfg(feature = "eth_personal")]
            Credential::EthPersonalSign(c) => c,
            #[cfg(feature = "cosmos")]
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


impl Credential {

    pub fn name(&self) -> CredentialName {
        self.discriminant()
    }


    pub fn message(&self) -> Vec<u8> {
        match self {
            Credential::Native(_) => Vec::new(),
            #[cfg(feature = "eth_personal")]
            Credential::EthPersonalSign(c) => c.message.to_vec(),
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.message.to_vec(),
            #[cfg(feature = "ed25519")]
            Credential::Ed25519(c) => c.message.to_vec(),
            #[cfg(feature = "secp256k1")]
            Credential::Secp256k1(c) => c.message.to_vec(),
            #[cfg(feature = "secp256r1")]
            Credential::Secp256r1(c) => c.message.to_vec(),
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c.base64_message_bytes().unwrap(),
        }
    }

    pub fn extension(&self) -> Result<Option<Binary>, AuthError> {
        #[cfg(all(feature = "passkeys", feature = "wasm"))]
        if let Credential::Passkey(c) = self {
            use saa_passkeys::passkey::*;
            return Ok(Some(saa_common::to_json_binary(&PasskeyInfo {
                origin: c.client_data.origin.clone(),
                cross_origin: c.client_data.cross_origin.clone(),
                pubkey: c.pubkey.clone().unwrap_or_default(),
                user_handle: c.user_handle.clone(),
                authenticator_data: c.authenticator_data.clone(),
            })?));
        }
        Ok(None)
    }

    pub fn info(&self) -> CredentialInfo {
        CredentialInfo {
            name: self.name(),
            hrp: self.hrp(),
            extension: self.extension().ok().flatten()
        }
    }

    
}




#[cfg(feature = "traits")]
use crate::CredentialsWrapper;

#[cfg(feature = "traits")]
impl crate::CredentialsWrapper for CredentialData {
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
    pub fn with_native<C: Into::<Caller>> (&self, cal: C) -> Self {
        if !self.use_native.unwrap_or(false) {
            return self.clone()
        }
        let caller : Caller = cal.into();
        let mut credentials = self.credentials.clone();

        match self.cred_index(CredentialName::Native, Some(caller.0.clone())) {
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


