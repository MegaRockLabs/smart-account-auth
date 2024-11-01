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
use saa_common::cosmwasm;

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
            } 
        }
    }

    
}

impl Verifiable for Credential {

    fn id(&self) -> CredentialId {
        match self {
            Credential::Caller(c) => c.id(),
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c.id(),
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.id(),
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c.id(),
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c.id(),
                    Credential::Secp256r1(c) => c.id(),
                    Credential::Ed25519(c) => c.id(),
                    _ => unreachable!(),
                }
            }
            
        }
    }

    fn info(&self) -> CredentialInfo {
        match self {
            Credential::Caller(c) => c.info(),
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c.info(),
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.info(),
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c.info(),
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c.info(),
                    Credential::Secp256r1(c) => c.info(),
                    Credential::Ed25519(c) => c.info(),
                    _ => unreachable!(),
                }
            }
        }
    }

    fn message(&self) -> saa_common::Binary {
        match self {
            Credential::Caller(c) => c.message(),
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c.message(),
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.message(),
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c.message(),
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c.message(),
                    Credential::Secp256r1(c) => c.message(),
                    Credential::Ed25519(c) => c.message(),
                    _ => unreachable!(),
                }
            }
        }
    }

    fn validate(&self) -> Result<(), AuthError> {
        match self {
            Credential::Caller(c) => c.validate(),
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c.validate(),
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.validate(),
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c.validate(),
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c.validate(),
                    Credential::Secp256r1(c) => c.validate(),
                    Credential::Ed25519(c) => c.validate(),
                    _ => unreachable!(),
                }
            }
        }
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.validate()?;
        match self {
            Credential::Caller(c) => c.verify(),
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c.verify(),
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.verify(),
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c.verify(),
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c.verify(),
                    Credential::Secp256r1(c) => c.verify(),
                    Credential::Ed25519(c) => c.verify(),
                    _ => unreachable!(),
                }
            }
        }
    }

    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(
        &self, api:  
        &dyn cosmwasm::Api, 
        env: &cosmwasm::Env, 
    ) -> Result<(), AuthError> {
        match self {
            Credential::Caller(c) => c.verify_cosmwasm(api, env)?,
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c.verify_cosmwasm(api, env)?,
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.verify_cosmwasm(api, env)?,
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c.verify_cosmwasm(api, env)?,
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c.verify_cosmwasm(api, env)?,
                    Credential::Secp256r1(c) => c.verify_cosmwasm(api, env)?,
                    Credential::Ed25519(c) => c.verify_cosmwasm(api, env)?,
                    _ => unreachable!(),
                }
            }
        };

        Ok(())
    }

}



#[cfg(all(feature = "cosmwasm", feature = "storage"))]
pub fn load_credential(
    storage:  &dyn Storage,
    message:  Binary,
    signature: Binary,
    payload:  Option<AuthPayload>,
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
                VERIFYING_CRED_ID.load(storage)?
            }
        }
        None => {
            VERIFYING_CRED_ID.load(storage)?
        }
    };
    let info = CREDENTIAL_INFOS.load(storage, initial_id.clone())?;
    construct_credential(id, info, message, signature, payload)
}


#[cfg(all(feature = "cosmwasm", feature = "storage"))]
pub fn get_all_credentials(
    storage:  &dyn Storage,
) -> Result<AccountCredentials, AuthError> {
    let credentials = CREDENTIAL_INFOS
        .range(storage, None, None, Order::Ascending)
        .map(|item| {
            let (id, info) = item?;
            let human_id = match info.name == CredentialName::Passkey {
                false => String::from_utf8(id.clone()).unwrap(),
                true => Binary(id.clone()).to_base64(),
            };
            Ok(CredentialFullInfo {
                id,
                human_id,
                name: info.name,
                hrp: info.hrp,
                extension: info.extension,
            })
        })
        .collect::<Result<Vec<CredentialFullInfo>, AuthError>>()?;

    let verifying_id = VERIFYING_CRED_ID.load(storage)?;
    let caller = CALLER.load(storage).unwrap_or(None);

    Ok(AccountCredentials {
        credentials,
        native_caller: caller.is_some(),
        verifying_human_id: Binary(verifying_id.clone()).to_base64(),
        verifying_id: verifying_id,
    })

}






pub fn construct_credential(
    id: CredentialId,
    info: CredentialInfo,
    message: Binary,
    signature: Binary,
    payload:  Option<AuthPayload>,
) -> Result<Credential, AuthError> {

    let credential = match info.name {

        CredentialName::Caller => Credential::Caller(saa_custom::caller::Caller { id }),

        #[cfg(feature = "ethereum")]
        CredentialName::EthPersonalSign => {
            let signer = match payload {
                Some(payload) => {
                    ensure!(
                        payload.hrp.is_none(),
                        AuthError::generic("Cannot use 'hrp' with EVM credentials")
                    );
                    match payload.address.as_ref() {
                        Some(address) => address.clone(),
                        None => String::from_utf8(id)?,
                    }
                }
                None => String::from_utf8(id)?,
            };
            Credential::EthPersonalSign(saa_custom::eth::EthPersonalSign {
                message,
                signature,
                signer,
            })
        }

        #[cfg(feature = "cosmos")]
        CredentialName::CosmosArbitrary => Credential::CosmosArbitrary(saa_custom::cosmos::CosmosArbitrary {
            pubkey: Binary(id),
            message,
            signature,
            hrp: payload.clone().map(|p| p.hrp).unwrap_or(info.hrp),
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
            
            ensure!(
                info.extension.is_some(),
                AuthError::generic("No stored public key for givem 'passkey' id")
            );
            ensure!(
                payload_ext.pubkey.is_some() || stored_ext.pubkey.is_some(),
                AuthError::generic("No public key provided for 'passkey'")
            );
            Credential::Passkey(PasskeyCredential {
                pubkey: Some(payload_ext.pubkey.unwrap_or(stored_ext.pubkey.unwrap())),
                authenticator_data: payload_ext.authenticator_data,
                client_data: payload_ext.client_data,
                user_handle: payload_ext.user_handle.or(stored_ext.user_handle),
                id: String::from_utf8(id)?,
                signature,
            })
        },

        #[cfg(feature = "curves")]
        curves => {
            match curves {
                CredentialName::Secp256k1 => Credential::Secp256k1(saa_curves::secp256k1::Secp256k1 {
                    pubkey: Binary(id),
                    signature,
                    message,
                    hrp: payload.clone().map(|p| p.hrp).unwrap_or(info.hrp),
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
