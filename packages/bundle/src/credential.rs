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
            }
        }
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
        self.validate()?;
        self.value().verify()
    }

    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(
        &self, api:  
        &dyn cosmwasm::Api, 
        env: &cosmwasm::Env, 
        info: &Option<cosmwasm::MessageInfo>
    ) -> Result<Self, AuthError> 
        where Self: Clone
    {
        self.validate()?;
        Ok(match self {
            Credential::Caller(c) => Credential::Caller(c.verified_cosmwasm(api, env, info)?),

            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => Credential::EthPersonalSign(
                c.verified_cosmwasm(api, env, info)?
            ),

            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => Credential::CosmosArbitrary(
                c.verified_cosmwasm(api, env, info)?
            ),

            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => Credential::Passkey(
                c.verified_cosmwasm(api, env, info)?
            ),

            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) 
                        => Credential::Secp256k1(c.verified_cosmwasm(api, env, info)?),

                    Credential::Secp256r1(c) 
                        => Credential::Secp256r1(c.verified_cosmwasm(api, env, info)?),

                    Credential::Ed25519(c) 
                        => Credential::Ed25519(c.verified_cosmwasm(api, env, info)?),

                    _ => unreachable!(),
                }
            }
        })
    }

}



#[cfg(all(feature = "cosmwasm", feature = "storage"))]
pub fn load_credential(
    storage:  &dyn saa_common::cosmwasm::Storage,
    message:  Binary,
    signature: Binary,
    payload:  Option<AuthPayload>,
) -> Result<Credential, AuthError> {
    use saa_common::storage::{CREDENTIAL_INFOS, VERIFYING_CRED_ID};

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
            ensure!(
                payload.is_some(),
                AuthError::generic("Payload must be provided for 'passkey'")
            );
            let payload = payload.as_ref().unwrap();
            ensure!(
                payload.extension.is_some(),
                AuthError::generic("Extension must be provided for 'passkey'")
            );
            ensure!(
                info.extension.is_some(),
                AuthError::generic("No stored public key for givem 'passkey' id")
            );
            let ext : saa_custom::passkey::PasskeyExtension = from_json(payload.extension.as_ref().unwrap())?;

            Credential::Passkey(saa_custom::passkey::PasskeyCredential {
                pubkey: Some(info.extension.unwrap().into()),
                authenticator_data: ext.authenticator_data,
                client_data: ext.client_data,
                user_handle: ext.user_handle,
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
    };

    Ok(credential)
}
