#[cfg(all(feature = "wasm", feature = "storage"))]
use saa_common::{
    CredentialId, CredentialName, AuthError, Binary, ensure, 
    cosmwasm::{Api, Env, Storage},
    storage::*,
    messages::*
};
#[cfg(all(feature = "wasm", feature = "storage"))]
use crate::Credential;



#[cfg(all(feature = "wasm", feature = "storage", feature = "iterator"))]
pub fn get_all_credentials(
    storage:  &dyn Storage,
) -> Result<AccountCredentials, AuthError> {

    let credentials = get_credentials(storage)?;

    let verifying_id = VERIFYING_CRED_ID.load(storage)?;
    let caller = CALLER.load(storage).unwrap_or(None);

    Ok(AccountCredentials {
        credentials,
        native_caller: caller.is_some(),
        verifying_id: Binary::new(verifying_id),
    })

}



#[cfg(all(feature = "wasm", feature = "storage"))]
pub fn reset_credentials(
    storage: &mut dyn Storage,
) -> Result<(), AuthError> {
    VERIFYING_CRED_ID.remove(storage);
    CALLER.remove(storage);
    #[cfg(feature = "secretwasm")]
    {
        let keys : Vec<CredentialId> = CREDENTIAL_INFOS
            .iter_keys(storage)?.map(|k| k.unwrap()).collect();

        for key in keys {
            CREDENTIAL_INFOS.remove(storage, &key)?;
        }
    }
    #[cfg(not(feature = "secretwasm"))]
    CREDENTIAL_INFOS.clear(storage);

    Ok(())
}


#[cfg(all(feature = "wasm", feature = "storage"))]
pub fn verify_signed_queries(
    api: &dyn Api,
    storage: &dyn Storage,
    env: &Env,
    data: SignedDataMsg
) -> Result<(), AuthError> {
    let credential = load_credential(storage, data)?;
    credential.assert_query_cosmwasm(api, storage, env)?;
    Ok(())
}

#[cfg(all(feature = "wasm", feature = "replay"))]
pub fn verify_signed_actions(
    api: &dyn Api,
    storage: &mut dyn Storage,
    env: &Env,
    data: SignedDataMsg
) -> Result<(), AuthError> {
    let credential = load_credential(storage, data)?;
    credential.assert_execute_cosmwasm(api, storage, env)?;
    Ok(())
}


#[cfg(all(feature = "wasm", feature = "storage"))]
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
    let info = get_cred_info(storage, id.clone())?;

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


#[cfg(all(feature = "wasm", feature = "storage"))]
fn construct_credential(
    id: CredentialId,
    name: CredentialName,
    hrp: Option<String>,
    stored_extension: Option<Binary>,
    passed_extension: Option<Binary>,
    message: Binary,
    signature: Binary,
) -> Result<Credential, AuthError> {
    use saa_common::from_json;


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
            pubkey: Binary::new(id),
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
            not(feature = "passkeys"), 
            not(feature = "cosmos"), 
            not(feature = "ethereum"))
        )]
        _ => return Err(AuthError::generic("Credential is not enabled")),
    };

    Ok(credential)
}