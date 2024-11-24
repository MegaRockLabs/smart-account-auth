use saa_common::{to_json_binary, AuthError, Binary, CredentialId, CredentialInfo, CredentialName, Verifiable 
};
use saa_custom::caller::Caller;
use saa_schema::wasm_serde;

#[cfg(feature = "curves")]
use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1, secp256r1::Secp256r1};

#[cfg(feature = "passkeys")]
use saa_custom::passkey::PasskeyCredential;

#[cfg(feature = "ethereum")]
use saa_custom::eth::EthPersonalSign;

#[cfg(feature = "cosmos")]
use saa_custom::cosmos::CosmosArbitrary;

#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Addr, Env, MessageInfo};

#[cfg(all(feature = "cosmwasm", feature = "storage"))]
use saa_common::{storage::*, cosmwasm::Storage, messages::*, ensure, from_json};


#[wasm_serde]
pub enum Credential {
    Caller(Caller),

    #[cfg(feature = "ethereum")]
    EthPersonalSign(EthPersonalSign),

    #[cfg(feature = "cosmos")]
    CosmosArbitrary(CosmosArbitrary),

    #[cfg(feature = "passkeys")]
    Passkey(PasskeyCredential),

    #[cfg(feature = "curves")]
    Secp256k1(Secp256k1),

    #[cfg(feature = "curves")]
    Secp256r1(Secp256r1),
    
    #[cfg(feature = "curves")]
    Ed25519(Ed25519),
}

/* impl Deref for Credential {
    type Target = dyn Verifiable;

    fn deref(&self) -> &Self::Target {
        self.value()
    }
} */

impl Credential {

    pub fn name(&self) -> CredentialName {
        match self {
            Credential::Caller(_) => CredentialName::Caller,
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(_) => CredentialName::EthPersonalSign,
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(_) => CredentialName::CosmosArbitrary,
            #[cfg(feature = "passkeys")]
            Credential::Passkey(_) => CredentialName::Passkey,
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(_) => CredentialName::Secp256k1,
                    Credential::Secp256r1(_) => CredentialName::Secp256r1,
                    Credential::Ed25519(_) => CredentialName::Ed25519,
                    _ => unreachable!(),
                }
            },
        }
    }

    pub fn value(&self) -> &dyn Verifiable {
        match self {
            Credential::Caller(c) => c,
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c,
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c,
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c,
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

    pub fn message(&self) -> &[u8] {
        match self {
            Credential::Caller(_) => &[],
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c.message.as_ref(),
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.message.as_ref(),
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => &c.client_data.challenge,
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => &c.message,
                    Credential::Secp256r1(c) => &c.message,
                    Credential::Ed25519(c) => &c.message,
                    _ => unreachable!(),
                }
            },
        }
    }

    pub fn extension(&self) -> Result<Option<Binary>, AuthError> {
        if let Credential::Passkey(c) = self {
            use saa_custom::passkey::*;
            return Ok(Some(to_json_binary(&PasskeyExtension {
                ty: c.client_data.ty.clone(),
                origin: c.client_data.origin.clone(),
                pubkey: c.pubkey.clone(),
                user_handle: c.user_handle.clone(),
            })?));
        } else {
            Ok(None)
        }
    }

    pub fn info(&self) -> CredentialInfo {
        CredentialInfo {
            name: self.name(),
            hrp: self.hrp(),
            extension: self.extension().unwrap_or(None),
        }
    }

    #[cfg(feature = "cosmwasm")]
    pub fn is_cosmos_derivable(&self) -> bool {
        self.hrp().is_some()
    }

    #[cfg(feature = "cosmwasm")]
    pub fn cosmos_address(&self, api: &dyn Api) -> Result<Addr, AuthError> {
        let name = self.name();
        if name == CredentialName::Caller {
            let address =  String::from_utf8(self.id())
                    .map(|s| Addr::unchecked(s))?;
            return Ok(address)
        }
        #[cfg(all(feature = "injective", feature="ethereum"))]
        {
            if name == CredentialName::EthPersonalSign {
                return Ok(Addr::unchecked(
                    saa_common::utils::pubkey_to_address(
                        &self.id(), "inj"
                    )?
                ))
            } 
        }
        Ok(match self.hrp() {
            Some(hrp) => Addr::unchecked(
                saa_common::utils::pubkey_to_address(&self.id(), &hrp)?
            ),
            None => {
                let canon = saa_common::utils::pubkey_to_canonical(&self.id());
                let addr = api.addr_humanize(&canon)?;
                addr
            }
        })
    }


    #[cfg(all(feature = "cosmwasm", feature = "storage"))]
    pub fn assert_query_cosmwasm(
        &self, 
        api     :  &dyn Api, 
        storage :  &dyn Storage,
        env     :  &Env, 
    ) -> Result<String, AuthError> 
        where Self: Sized
    {   
        ensure!(CREDENTIAL_INFOS.has(storage, self.id()), AuthError::NotFound);
        self.verify_cosmwasm(api, env)?;
        #[cfg(feature = "replay")]
        if true {
            let msg : MsgDataToVerify = from_json(&self.message())?;
            msg.validate_cosmwasm(storage, env)?;
            return Ok(msg.nonce.clone())
        }
        Ok(String::default())
    }

    #[cfg(all(feature = "cosmwasm", feature = "storage"))]
    pub fn assert_execute_cosmwasm(
        &self, 
        api     :  &dyn Api,
        #[cfg(feature = "replay")]
        storage :  &mut dyn Storage,
        #[cfg(not(feature = "replay"))]
        storage :  &dyn Storage,
        env     :  &Env, 
    ) -> Result<(), AuthError> 
        where Self: Sized
    {
        let nonce = self.assert_query_cosmwasm(api, storage, env)?;
        if !nonce.is_empty() {
            NONCES.save(storage, &nonce, &true)?;
        }
        Ok(())
    }

    #[cfg(all(feature = "cosmwasm", feature = "storage"))]
    pub fn save_cosmwasm(&self, 
        api: &dyn Api, 
        storage: &mut dyn Storage,
        env:  &Env,
        info: &MessageInfo
    ) -> Result<(), AuthError> {
        CREDENTIAL_INFOS.save(storage, self.id(), &self.info())?;
        self.assert_execute_cosmwasm(api, storage, env)?;
        if let Credential::Caller(_) = self {
            CALLER.save(storage, &Some(info.sender.to_string()))?;
        }
        Ok(())
    }

    
}

impl Verifiable for Credential {

    fn id(&self) -> CredentialId {
        self.value().id()
    }

    fn hrp(&self) -> Option<String> {
        self.value().hrp()
    }

    fn validate(&self) -> Result<(), AuthError> {
        self.value().validate()
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.value().verify()
    }

    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&self,  api:  &dyn Api,  env:  &Env) -> Result<(), AuthError>  
        where Self: Sized
    {
        self.validate()?;
        match self {
            Credential::Caller(c) => c.verify_cosmwasm(api, env),
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c.verify_cosmwasm(api, env),
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.verify_cosmwasm(api, env),
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c.verify_cosmwasm(api, env),
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c.verify_cosmwasm(api, env),
                    Credential::Secp256r1(c) => c.verify_cosmwasm(api, env),
                    Credential::Ed25519(c) => c.verify_cosmwasm(api, env),
                    _ => unreachable!(),
                }
            },
        }
    }

}






