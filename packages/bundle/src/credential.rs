#![allow(unreachable_code)]
use saa_common::{to_json_binary, AuthError, Binary, CredentialId, CredentialInfo, CredentialName, Verifiable};
use saa_auth::caller::Caller;
use saa_schema::wasm_serde;

#[cfg(feature = "curves")]
use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1, secp256r1::Secp256r1};

#[cfg(all(not(feature = "curves"), feature = "ed25519"))]
use saa_curves::ed25519::Ed25519;

#[cfg(feature = "passkeys")]
use saa_auth::passkey::PasskeyCredential;

#[cfg(feature = "ethereum")]
use saa_auth::eth::EthPersonalSign;

#[cfg(feature = "cosmos")]
use saa_auth::cosmos::CosmosArbitrary;


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
    
    #[cfg(any(feature = "curves", feature = "ed25519" ))]
    Ed25519(Ed25519),
}


impl Credential {

    pub fn name(&self) -> CredentialName {
        match self {
            Credential::Caller(_) => CredentialName::Caller,
            #[cfg(feature = "passkeys")]
            Credential::Passkey(_) => CredentialName::Passkey,
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(_) => CredentialName::EthPersonalSign,
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(_) => CredentialName::CosmosArbitrary,
            #[cfg(all(not(feature = "curves"), feature = "ed25519"))]
            Credential::Ed25519(_) => CredentialName::Ed25519,
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

    fn value(&self) -> &dyn Verifiable {
        match self {
            Credential::Caller(c) => c,
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

    pub fn message(&self) -> Vec<u8> {
        match self {
            Credential::Caller(_) => Vec::new(),
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c.message.to_vec(),
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.message.to_vec(),
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => {
                let base64 =  saa_auth::passkey::utils::url_to_base64(&c.client_data.challenge);
                Binary::from_base64(&base64).unwrap().to_vec()
            },
            #[cfg(all(not(feature = "curves"), feature = "ed25519"))]
            Credential::Ed25519(c) => c.message.to_vec(),
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
            name: self.name(),
            hrp: self.hrp(),
            extension: self.extension().unwrap_or(None),
        }
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

    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self,  api:  &dyn saa_common::wasm::Api) -> Result<(), AuthError>  
        where Self: Sized
    {
        self.validate()?;
        match self {
            Credential::Caller(c) => c.verify_cosmwasm(api),
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c.verify_cosmwasm(api),
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c.verify_cosmwasm(api),
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.verify_cosmwasm(api),
            #[cfg(all(not(feature = "curves"), feature = "ed25519"))]
            Credential::Ed25519(c) => c.verify_cosmwasm(api),
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c.verify_cosmwasm(api),
                    Credential::Secp256r1(c) => c.verify_cosmwasm(api),
                    Credential::Ed25519(c) => c.verify_cosmwasm(api),
                    _ => unreachable!(),
                }
            },
        }
    }

}






pub fn construct_credential(
    id: CredentialId,
    name: CredentialName,
    message: Binary,
    signature: Binary,
    hrp: Option<String>,
    stored_extension: Option<Binary>,
    passed_extension: Option<Binary>,
) -> Result<Credential, AuthError> {
    
    let credential = match name {

        CredentialName::Caller => Credential::Caller(saa_auth::caller::Caller { id }),

        #[cfg(feature = "ethereum")]
        CredentialName::EthPersonalSign => Credential::EthPersonalSign(saa_auth::eth::EthPersonalSign {
                message,
                signature,
                signer: String::from_utf8(id)?,
            }
        ),

        #[cfg(feature = "cosmos")]
        CredentialName::CosmosArbitrary => Credential::CosmosArbitrary(saa_auth::cosmos::CosmosArbitrary {
            pubkey: Binary::new(id),
            message,
            signature,
            hrp,
        }),

        #[cfg(feature = "passkeys")]
        CredentialName::Passkey => {
            use saa_common::{from_json, ensure};
            use saa_auth::passkey::*;
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
            let challenge = saa_auth::passkey::utils::base64_to_url(&message.to_base64());
            let client_data = ClientData::new(
                "webauthn.get".into(),
                challenge,
                stored_ext.origin,
                stored_ext.cross_origin,
                payload_ext.other_keys.unwrap_or_default()
            );
            Credential::Passkey(PasskeyCredential {
                id: String::from_utf8(id)?,
                pubkey,
                signature,
                client_data,
                authenticator_data: payload_ext.authenticator_data,
                user_handle: stored_ext.user_handle,
            })
        },
        #[cfg(all(not(feature = "curves"), feature = "ed25519"))]
        CredentialName::Ed25519 => Credential::Ed25519(saa_curves::ed25519::Ed25519 {
            pubkey: Binary::new(id),
            signature,
            message,
        }),
        #[cfg(feature = "curves")]
        curves => {
            let pubkey = Binary::new(id);
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
            not(feature = "ed25519"),
            not(feature = "passkeys"), 
            not(feature = "cosmos"), 
            not(feature = "ethereum"))
        )]
        _ => return Err(AuthError::generic("Credential is not enabled")),
    };

    Ok(credential)
}