
#[cfg(feature = "eth_personal")]
pub use saa_auth::eth::EthPersonalSign;
#[cfg(feature = "eth_typed_data")]
pub use saa_auth::eth::EthTypedData;
#[cfg(any(feature = "cosmos_arb", feature = "cosmos_arb_addr"))]
pub use saa_auth::cosmos::CosmosArbitrary;
#[cfg(feature = "passkeys")]
pub use saa_passkeys::passkey::PasskeyCredential;
#[cfg(feature = "secp256r1")]
pub use saa_passkeys::secp256r1::Secp256r1;
#[cfg(feature = "secp256k1")]
pub use saa_curves::secp256k1::Secp256k1;
#[cfg(feature = "ed25519")]
pub use saa_curves::ed25519::Ed25519;
use strum::IntoDiscriminant;

pub use crate::caller::Caller;
pub use saa_common::{CredentialId, CredentialName, CredentialInfo, CredentialRecord};
use saa_schema::saa_type;




#[saa_type]
pub enum Credential {
    Native(Caller),
    #[cfg(feature = "eth_personal")]
    EthPersonalSign(EthPersonalSign),
    #[cfg(any(feature = "cosmos_arb", feature = "cosmos_arb_addr"))]
    CosmosArbitrary(CosmosArbitrary),
    #[cfg(feature = "passkeys")]
    Passkey(PasskeyCredential),
    #[cfg(feature = "secp256r1")]
    Secp256r1(Secp256r1),
    #[cfg(feature = "secp256k1")]
    Secp256k1(Secp256k1),
    #[cfg(feature = "ed25519")]
    Ed25519(Ed25519),
}

impl IntoDiscriminant for Credential {
    type Discriminant = CredentialName;
    fn discriminant(&self) -> Self::Discriminant {
        match self {
            Credential::Native(_) => CredentialName::Native,
            #[cfg(feature = "eth_personal")]
            Credential::EthPersonalSign(_) => CredentialName::EthPersonalSign,
            #[cfg(any(feature = "cosmos_arb", feature = "cosmos_arb_addr"))]
            Credential::CosmosArbitrary(_) => CredentialName::CosmosArbitrary,
            #[cfg(feature = "passkeys")]
            Credential::Passkey(_) => CredentialName::Passkey,
            #[cfg(feature = "secp256r1")]
            Credential::Secp256r1(_) => CredentialName::Secp256r1,
            #[cfg(feature = "secp256k1")]
            Credential::Secp256k1(_) => CredentialName::Secp256k1,
            #[cfg(feature = "ed25519")]
            Credential::Ed25519(_) => CredentialName::Ed25519,
        }
    }
}



#[allow(unused, dead_code)]
#[cfg(feature = "wasm")]
pub fn build_credential(
    record      : CredentialRecord,
    msg         : crate::msgs::SignedDataMsg,
    payload     : Option<saa_common::types::cred::PayloadExtension>,
) -> Result<Credential, saa_common::AuthError> {
    let (id, info) = record;
    let message = msg.data;
    let signature = msg.signature;
    let name = info.name;
    
    let credential = match name {

        CredentialName::Native => Credential::Native(Caller(id)),

        #[cfg(feature = "eth_personal")]
        CredentialName::EthPersonalSign => Credential::EthPersonalSign(EthPersonalSign {
                message,
                signature,
                signer: id,
            }
        ),

        #[cfg(any(feature = "cosmos_arb", feature = "cosmos_arb_addr"))]
        CredentialName::CosmosArbitrary => Credential::CosmosArbitrary(CosmosArbitrary {
            pubkey: saa_common::Binary::from_base64(&id)?,
            message,
            signature,
            #[cfg(not(feature = "cosmos_arb_addr"))]
            hrp: info.hrp,
            #[cfg(feature = "cosmos_arb_addr")]
            address: info.address
                .ok_or_else(|| saa_common::AuthError::generic("Missing address in CosmosArbitrary credential"))?
                .to_string(),
        }),

        #[cfg(feature = "passkeys")]
        CredentialName::Passkey => {
            use saa_passkeys::passkey::{
                ClientData, PasskeyExtension, PasskeyPayload, 
                utils::base64_to_url
            };
            let stored_info = if let Some(ext) = info.extension {
                match ext {
                    saa_common::InfoExtension::Passkey(stored) => stored,
                    _ => {
                        return Err(saa_common::AuthError::generic("Unsupported passkey extension type"));
                    }
                } 
            } else {
                return Err(saa_common::AuthError::generic("Passkey info is not provided"));
            };

            let (origin, other_keys) = match payload {
                Some(payload) => {
                    match payload {
                        saa_common::types::cred::PayloadExtension::Passkey(passkey_payload) => {
                            (passkey_payload.origin, passkey_payload.other_keys)
                        },
                        _ => {
                            return Err(saa_common::AuthError::generic("Unsupported passkey payload type"));
                        }
                        
                    }
                },
                None => (None, None),
            };
            
            let client_data = ClientData::new(
                base64_to_url(message.to_base64().as_str()),
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

        #[cfg(feature = "secp256r1")]
        CredentialName::Secp256r1 => Credential::Secp256r1(Secp256r1 {
            pubkey: saa_common::Binary::from_base64(&id)?,
            signature,
            message,
        }),
        #[cfg(feature = "secp256k1")]
        CredentialName::Secp256k1 => Credential::Secp256k1(Secp256k1 {
            pubkey: saa_common::Binary::from_base64(&id)?,
            signature,
            message,
            hrp: info.hrp,
        }),
        #[cfg(feature = "ed25519")]
        CredentialName::Ed25519 => Credential::Ed25519(Ed25519 {
            pubkey: saa_common::Binary::from_base64(&id)?,
            signature,
            message,
        }),
    };
    Ok(credential)
}


