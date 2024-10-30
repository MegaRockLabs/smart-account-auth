
use saa_common::{
    ensure, format, vec, Binary, 
    CredentialId, CredentialInfo, CredentialName, 
    Vec, Verifiable, AuthError
};
use saa_custom::caller::Caller;
use saa_schema::wasm_serde;

#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env, MessageInfo, Storage};
#[cfg(feature = "substrate")]
use saa_common::substrate::{InkEnvironment, InkApi};

use crate::{Credential, CredentialsWrapper};


#[wasm_serde]
pub struct CredentialData {
    pub credentials     :  Vec<Credential>,
    pub with_caller     :  Option<bool>,
    pub primary_index   :  Option<u8>,
}


impl Default for CredentialData {
    fn default() -> Self {
        Self { 
            credentials     : vec![], 
            with_caller     : None,
            primary_index   : None, 
        }
    }
}

impl CredentialData {

    pub fn new(
        credentials: Vec<Credential>, 
        primary_index: Option<u8>, 
        with_caller: Option<bool>,
    ) -> Self {
        Self { 
            credentials, 
            primary_index,
            with_caller,
        }
    }

    pub fn values(&self) -> Vec<&dyn Verifiable> {
        self.credentials.iter().map(|c| c.value()).collect()
    }

    pub fn find_by_name(&self, name: CredentialName) -> Option<Credential> {
        self.credentials
            .iter()
            .find(|c| c.name() == name)
            .cloned()
    }

    pub fn find_by_id(&self, id: &CredentialId) -> Option<Credential> {
        self.credentials
            .iter()
            .find(|c| c.id() == *id)
            .cloned()
    }



    pub fn with_caller<C: Into::<Caller>> (&self, cal: C) -> Self {
        let mut credentials = self.credentials.clone();

        let existing = credentials.iter()
                .position(|c| c.name() == CredentialName::Caller);

        if let Some(index) = existing {
            credentials[index] = Credential::Caller(cal.into());
        } else {
            credentials.push(Credential::Caller(cal.into()));
        }
        Self {
            credentials,
            with_caller: Some(true),
            primary_index: self.primary_index,
        }
    }


    #[cfg(feature = "substrate")]
    pub fn with_caller_ink(&self, id: impl AsRef<[u8]>) -> Self {
        self.with_caller(id.as_ref())
    }
    

    #[cfg(feature = "cosmwasm")]
    pub fn with_caller_cosmwasm(&self, info: &saa_common::cosmwasm::MessageInfo) -> Self  {
        self.with_caller(info)
    }

    #[cfg(feature = "cosmwasm")]
    fn is_cosmos_derivable(&self) -> bool {
        self.credentials.len() > 0 &&
        (
            self.credentials.iter().any(
                |c|  {
                    let name = c.name();
                    if name == CredentialName::Caller {
                        return true;
                    }
                    if saa_common::constants::IS_INJECTIVE {
                        name == CredentialName::EthPersonalSign
                    } else {
                        name == CredentialName::CosmosArbitrary ||
                        name == CredentialName::Secp256k1
                    }
                }
            ) 
        )
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

    fn info(&self) -> CredentialInfo {
        self.primary().info()
    }

    fn message(&self) -> Binary {
        self.primary().message()
    }

    fn validate(&self) -> Result<(), AuthError> {
        let creds = self.credentials();

        let with_caller = self.with_caller.unwrap_or(false);
        if !with_caller && creds.len() == 0 {
            return Err(AuthError::NoCredentials);
        } else if creds.len() > 255 {
            return Err(AuthError::Generic(format!("Too many credentials: {}", creds.len())));
        }

        if let Some(index) = self.primary_index() {
            let len = creds.len() + if with_caller { 1 } else { 0 };
            if *index as usize >= len {
                return Err(AuthError::Generic(format!("Primary index {} is out of bounds", index)));
            }
        }
        creds.iter().map(|c| c.validate()).collect()
    }


    #[cfg(all(feature = "cosmwasm", feature = "replay"))]
    fn validate_signed_data(&self, storage: &dyn Storage, env: &Env) -> Result<String, AuthError> {
        use saa_common::messages::SignedData;
        let first = self.credentials().first().unwrap();
        let signed : SignedData<String> = saa_common::from_json(&first.message())?;
        let data = &signed.data;
        let nonce = Verifiable::validate_signed_data(first, storage, env)?;
        
        self.credentials().iter().skip(1).map(|c| {
            let signed : SignedData<String> = saa_common::from_json(&c.message())?;
            let cred_data = &signed.data;
            ensure!(cred_data.chain_id == data.chain_id, AuthError::ChainIdMismatch);
            ensure!(cred_data.contract_address == data.contract_address, AuthError::ContractMismatch);
            ensure!(cred_data.nonce == nonce, AuthError::DifferentNonce);
            Ok(())
        }).collect::<Result<Vec<()>, AuthError>>()?;

        Ok(nonce)
    }
    

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.validate()?;
        self.credentials().iter().map(|c| c.verify()).collect()
    }


    #[cfg(feature = "substrate")]
    fn verified_ink<'a>(&self, api: InkApi<'a, impl InkEnvironment + Clone>) -> Result<Self, AuthError> {
        let with_caller = self.with_caller.unwrap_or(false);
        
        let creds = if with_caller {
            let caller = api.clone().caller();
            self.with_caller_ink(caller)
        } else {
            self.clone()
        };

        creds.validate()?;

        creds.credentials()
            .iter()
            .map(|c| c.verified_ink(api.clone())).
            collect::<Result<Vec<Credential>, AuthError>>()?;

        Ok(creds.clone())
    }


    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(&self, api: &dyn Api, env: &Env, info: &Option<MessageInfo>) -> Result<Self, AuthError>
    {
        let with_caller = self.with_caller.unwrap_or(false);

        let creds = if with_caller && info.is_some() {
            // inject a caller (info.sender) credential
            self.with_caller_cosmwasm(info.as_ref().unwrap())
        } else {
            // ignore and proceed without a caller (info.sender)
            self.clone()
        };

        creds.validate()?;

        let verified = creds.credentials()
                .iter()
                .map(|c| c.verified_cosmwasm(api, env, info)).
                collect::<Result<Vec<Credential>, AuthError>>()?;

        Ok(Self {
            credentials: verified,
            with_caller: self.with_caller,
            primary_index: creds.primary_index,
        })
    }

 
    #[cfg(feature = "cosmwasm")]
    fn cosmos_address(&self, api: &dyn Api) -> Result<saa_common::cosmwasm::Addr, AuthError> {
        ensure!(
            self.is_cosmos_derivable(), 
            AuthError::generic("No credentials derivaable into a cosmos address")
        );
        let cred = self.credentials
            .iter()
            .find(|c| c.is_cosmos_derivable());
        cred.unwrap().cosmos_address(api)
    }


    #[cfg(all(feature = "cosmwasm", feature = "storage"))]
    fn verify_and_save(
        &self, 
        api: &dyn Api, 
        storage: &mut dyn Storage,
        env: &Env, 
        info: &Option<MessageInfo>
    ) -> Result<Self, AuthError> 
        where Self: Clone 
    {
        use saa_common::storage::*;;

        self.validate()?;
        let verified = self.verified_cosmwasm(api, env, info)?;

        if saa_common::constants::IS_REPLAY_PROTECTION_ON {
            let nonce = verified.validate_signed_data(storage, env)?;
            NONCES.save(storage, nonce, &true)?;
        }  

        let mut verifying_found = false;

        if verified.primary_index.is_some() {
            if let Credential::Caller(_) = verified.primary() {
                // skio the caller since it is can't be used to verify messages
            } else {
                VERIFYING_CRED_ID.save(storage, &verified.primary_id())?;
                verifying_found = true;
            }
        }

        for cred in verified.credentials() {

            if let Credential::Caller(_) = cred {
                continue;
            }

            #[cfg(feature = "passkeys")]
            if let Credential::Passkey(pk) = cred {
                ensure!(
                    pk.pubkey.is_none(), 
                    AuthError::generic("Must pass a public key when creating passkeys")
                );
            }

            if !verifying_found {
                VERIFYING_CRED_ID.save(storage, &cred.id())?;
                verifying_found = true;
            }

            CREDENTIAL_INFOS.save(storage, cred.id(), &cred.info())?;
        }

        ensure!(verifying_found, AuthError::NoVerifying);
        Ok(verified)
        
    }


}