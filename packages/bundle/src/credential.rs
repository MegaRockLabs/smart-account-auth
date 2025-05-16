use saa_auth::caller::Caller;
use saa_schema::{saa_derivable, saa_type};

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

use saa_common::{AuthError, Binary, CredentialId};
use crate::msgs::SignedDataMsg;



#[saa_derivable(name(CredentialName))]
pub enum Credential {
    Native(Caller),

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






#[saa_type]
pub struct CredentialInfo {
    /// name of the used credential
    pub name: CredentialName,
    /// human readable prefix to encode from a public key
    pub hrp: Option<saa_common::String>,
    /// extension data
    pub extension: Option<saa_common::Binary>,
}



pub type CredentialRecord = (CredentialId, CredentialInfo);



#[allow(unused, dead_code)]
pub fn build_credential(
    record      : CredentialRecord,
    msg         : SignedDataMsg,
    extension   : Option<Binary>,
) -> Result<Credential, AuthError> {
    let (id, info) = record;
    let message = msg.data;
    let signature = msg.signature;
    let name = info.name;
    
    let credential = match name {

        CredentialName::Native => Credential::Native(saa_auth::caller::Caller(id)),

        #[cfg(feature = "ethereum")]
        CredentialName::EthPersonalSign => Credential::EthPersonalSign(saa_auth::eth::EthPersonalSign {
                message,
                signature,
                signer: id,
            }
        ),

        #[cfg(feature = "cosmos")]
        CredentialName::CosmosArbitrary => Credential::CosmosArbitrary(saa_auth::cosmos::CosmosArbitrary {
            pubkey: Binary::from_base64(&id)?,
            message,
            signature,
            hrp: info.hrp,
        }),

        #[cfg(feature = "passkeys")]
        CredentialName::Passkey => {
            use saa_common::from_json;
            use saa_auth::passkey::*;

     
            let stored_info  = info.extension
                .map(|e| from_json::<PasskeyInfo>(e).ok() )
                .flatten()
                .ok_or_else(|| AuthError::generic("Missing passkey info"))?;
            
            let (origin, other_keys) = match extension
                .map(|e| from_json::<PasskeyPayload>(e).ok())
                .flatten()
            {
                Some(payload) => (payload.origin, payload.other_keys),
                None => (None, None),
            };
            
            let client_data = ClientData::new(
                "webauthn.get",
                utils::base64_to_url(message.to_base64().as_str()),
                origin.unwrap_or(stored_info.origin),
                stored_info.cross_origin,
                other_keys
            );

            Credential::Passkey(PasskeyCredential {
                id,
                signature,
                client_data,
                pubkey: Some(stored_info.pubkey),
                authenticator_data: stored_info.authenticator_data,
                user_handle: stored_info.user_handle,
            })
        },
        #[cfg(all(not(feature = "curves"), feature = "ed25519"))]
        CredentialName::Ed25519 => Credential::Ed25519(saa_curves::ed25519::Ed25519 {
            pubkey: Binary::from_base64(&id)?,
            signature,
            message,
        }),
        #[cfg(feature = "curves")]
        curves => {
            let pubkey = Binary::from_base64(&id)?;
            match curves {
                CredentialName::Secp256k1 => Credential::Secp256k1(saa_curves::secp256k1::Secp256k1 {
                    pubkey,
                    signature,
                    message,
                    hrp: info.hrp,
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
                _ => return Err(saa_common::AuthError::generic("Unsupported curve")),
            }
        }
    };
    Ok(credential)
}