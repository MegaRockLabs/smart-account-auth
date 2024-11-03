use saa_common::{ensure, from_json, to_json_binary, AuthError, Binary, CredentialId, CredentialInfo, CredentialName, Verifiable 
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
        if true {
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
            let msg : MsgDataToSign = from_json(&self.message())?;
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
pub fn verify_signed_actions(
    api: &dyn Api,
    #[cfg(feature = "replay")]
    storage: &mut dyn Storage,
    #[cfg(not(feature = "replay"))]
    storage: &dyn Storage,
    env: &Env,
    data: SignedDataMsg
) -> Result<(), AuthError> {
    let credential = load_credential(storage, data)?;
    credential.assert_execute_cosmwasm(api, storage, env)?;
    Ok(())
}


#[cfg(all(feature = "cosmwasm", feature = "storage"))]
fn load_credential(
    storage:   &dyn Storage,
    data:      SignedDataMsg
) -> Result<Credential, AuthError> {
    let initial_id = VERIFYING_CRED_ID.load(storage)?;

    let id = match data.payload.clone() {
        Some(payload) => {
            payload.validate_cosmwasm(storage)?;
            if let Some(id) = payload.credential_id {
                id
            } else if let Some(address) = payload.address {
                address.as_bytes().to_vec()
            } else {
                initial_id
            }
        }
        None => {
            initial_id
        }
    };
    let info = CREDENTIAL_INFOS.load(storage, id.clone())?;

    construct_credential(
        id, 
        info.name,
        data.payload.as_ref().map(|p| p.hrp.clone()).unwrap_or(info.hrp),
        info.extension,
        data.payload.map(|p| p.extension).unwrap_or(None),
        data.data, 
        data.signature, 
    )
}


#[cfg(all(feature = "cosmwasm", feature = "storage"))]
fn construct_credential(
    id: CredentialId,
    name: CredentialName,
    hrp: Option<String>,
    stored_extension: Option<Binary>,
    passed_extension: Option<Binary>,
    message: Binary,
    signature: Binary,
) -> Result<Credential, AuthError> {

    let credential = match name {

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
            hrp,
        }),

        #[cfg(feature = "passkeys")]
        CredentialName::Passkey => {
            use saa_custom::passkey::*;
            ensure!(
                passed_extension.is_some(),
                AuthError::generic("Payload must be provided for 'passkey'")
            );
            ensure!(
                stored_extension.is_some(),
                AuthError::generic("Extension must be stored for 'passkey'")
            );
            let extensiom = passed_extension.unwrap();
            let payload_ext : PasskeyPayload = from_json(&extensiom)?;
            let stored_ext : PasskeyExtension = from_json(&stored_extension.unwrap())?;
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
                user_handle: stored_ext.user_handle,
            })
        },

        #[cfg(feature = "curves")]
        curves => {
            let pubkey = Binary(id);
            match curves {
                CredentialName::Secp256k1 => Credential::Secp256k1(saa_curves::secp256k1::Secp256k1 {
                    pubkey,
                    signature,
                    message,
                    hrp,
                }),
                CredentialName::Secp256r1 => Credential::Secp256r1(saa_curves::secp256r1::Secp256r1 {
                    pubkey,
                    signature,
                    message,
                }),
                CredentialName::Ed25519 => Credential::Ed25519(saa_curves::ed25519::Ed25519 {
                    pubkey,
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




#[cfg(all(feature = "cosmwasm", feature = "storage", feature = "iterator"))]
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




