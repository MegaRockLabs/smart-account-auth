use saa_common::{ensure, from_json, Binary, AuthError,
    CredentialId, CredentialInfo, CredentialName, Verifiable,
    messages::AuthPayload 
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
use saa_common::{storage::*, cosmwasm::{Storage, Order}, messages::*};


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

impl Credential {

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

    #[cfg(feature = "cosmwasm")]
    pub fn is_cosmos_derivable(&self) -> bool {
        let name = self.info().name;
        if name == CredentialName::Caller {
            return true;
        }
        #[cfg(feature = "injective")]
        if true {
            return name == CredentialName::EthPersonalSign;
        }
        name == CredentialName::CosmosArbitrary ||
        name == CredentialName::Secp256k1
    }

    #[cfg(feature = "cosmwasm")]
    pub fn cosmos_address(&self, api: &dyn Api) -> Result<Addr, AuthError> {
        let info = self.info();
        let name = info.name;
        if name == CredentialName::Caller {
            let address =  String::from_utf8(self.id())
                    .map(|s| Addr::unchecked(s))?;
            return Ok(address)
        }
        #[cfg(all(feature = "injective", feature="ethereum"))]
        if true {
            if name == CredentialName::EthPersonalSign {
                return Ok(Addr::unchecked(
                    saa_common::utils::pubkey_to_address(
                        &self.id(), "inj"
                    )?
                ))
            } 
        }
        Ok(match info.hrp {
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
            let msg : MsgDataToSign<()> = from_json(&self.message())?;
            msg.validate_cosmwasm(storage, env)?;
            let nonce = msg.nonce.clone();
            ensure!(!NONCES.has(storage, &nonce), AuthError::NonceUsed);
            return Ok(nonce)
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
        #[cfg(feature = "replay")] 
        if true {
            self.assert_execute_cosmwasm(api, storage, env)?;
        }
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

    fn info(&self) -> CredentialInfo {
        self.value().info()
    }

    fn message(&self) -> saa_common::Binary {
        self.value().message()
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



#[cfg(all(feature = "cosmwasm", feature = "storage"))]
pub fn load_credential(
    storage:   &dyn Storage,
    message:   Binary,
    signature: Binary,
    payload:   Option<AuthPayload>,
) -> Result<Credential, AuthError> {
    let initial_id = VERIFYING_CRED_ID.load(storage)?;

    let id = match payload.clone() {
        Some(payload) => {
            payload.validate_cosmwasm(storage)?;
            if let Some(id) = payload.credential_id {
                id
            } else if let Some(address) = payload.address {
                address.as_bytes().to_vec()
            } else {
                initial_id.clone()
            }
        }
        None => {
            initial_id.clone()
        }
    };
    let stored_info = CREDENTIAL_INFOS.load(storage, initial_id)?;
    let info = CredentialInfo {
        name: stored_info.name,
        hrp: payload.as_ref().map(|p| p.hrp.clone())
            .unwrap_or(stored_info.hrp),
        extension: payload.as_ref().map(|p| p.extension.clone())
            .unwrap_or(stored_info.extension),
    };
    construct_credential(id, info, message, signature, payload)
}



pub fn construct_credential(
    id: CredentialId,
    info: CredentialInfo,
    message: Binary,
    signature: Binary,
    payload: Option<AuthPayload>,
) -> Result<Credential, AuthError> {

    let credential = match info.name {

        CredentialName::Caller => Credential::Caller(saa_custom::caller::Caller { id }),

        #[cfg(feature = "ethereum")]
        CredentialName::EthPersonalSign => Credential::EthPersonalSign(saa_custom::eth::EthPersonalSign {
                message,
                signature,
                signer: String::from_utf8(id)?,
            }
        ),

        #[cfg(feature = "cosmos")]
        CredentialName::CosmosArbitrary => Credential::CosmosArbitrary(saa_custom::cosmos::CosmosArbitrary {
            pubkey: Binary(id),
            message,
            signature,
            hrp: info.hrp,
        }),

        #[cfg(feature = "passkeys")]
        CredentialName::Passkey => {
            use saa_custom::passkey::*;
            ensure!(
                payload.is_some(),
                AuthError::generic("Payload must be provided for 'passkey'")
            );
            let payload = payload.as_ref().unwrap();
            ensure!(
                payload.extension.is_some(),
                AuthError::generic("Extension must be provided for 'passkey'")
            );
            let payload_ext : PasskeyPayload = from_json(payload.extension.as_ref().unwrap())?;
            let stored_ext : PasskeyStore = from_json(info.extension.as_ref().unwrap())?;
            let pubkey = payload_ext.pubkey.or(stored_ext.pubkey);
            ensure!(
                pubkey.is_some(),
                AuthError::generic("No public key provided for 'passkey' credential")
            );
            Credential::Passkey(PasskeyCredential {
                id: String::from_utf8(id)?,
                pubkey,
                signature,
                authenticator_data: payload_ext.authenticator_data,
                client_data: payload_ext.client_data,
                user_handle: payload_ext.user_handle.or(stored_ext.user_handle),
            })
        },

        #[cfg(feature = "curves")]
        curves => {
            match curves {
                CredentialName::Secp256k1 => Credential::Secp256k1(saa_curves::secp256k1::Secp256k1 {
                    pubkey: Binary(id),
                    signature,
                    message,
                    hrp: info.hrp,
                }),
                CredentialName::Secp256r1 => Credential::Secp256r1(saa_curves::secp256r1::Secp256r1 {
                    pubkey: Binary(id),
                    signature,
                    message,
                }),
                CredentialName::Ed25519 => Credential::Ed25519(saa_curves::ed25519::Ed25519 {
                    pubkey: Binary(id),
                    signature,
                    message,
                }),
                _ => return Err(AuthError::generic("Unsupported curve")),
            }
        }
        #[cfg(any(
            not(feature = "curves"), 
            not(feature = "passkeys"), 
            not(feature = "cosmos"), 
            not(feature = "ethereum"))
        )]
        _ => return Err(AuthError::generic("Credential is not enabled")),
    };

    Ok(credential)
}




#[cfg(all(feature = "cosmwasm", feature = "storage"))]
pub fn get_all_credentials(
    storage:  &dyn Storage,
) -> Result<AccountCredentials, AuthError> {
    let credentials = CREDENTIAL_INFOS
        .range(storage, None, None, Order::Ascending)
        .map(|item| {
            let (id, info) = item?;
            Ok((
                Binary(id), 
                CredentialInfo {
                    name: info.name,
                    hrp: info.hrp,
                    extension: info.extension,
            }))
        })
        .collect::<Result<Vec<(Binary, CredentialInfo)>, AuthError>>()?;

    let verifying_id = VERIFYING_CRED_ID.load(storage)?;
    let caller = CALLER.load(storage).unwrap_or(None);

    Ok(AccountCredentials {
        credentials,
        native_caller: caller.is_some(),
        verifying_id: Binary(verifying_id),
    })

}




