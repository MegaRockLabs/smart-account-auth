use saa_schema::{saa_derivable, saa_type};
use saa_common::{Binary, String, CredentialId};

pub use super::caller::Caller;
#[cfg(feature = "eth_personal")]
pub use saa_auth::eth::EthPersonalSign;
#[cfg(feature = "cosmos")]
pub use saa_auth::cosmos::CosmosArbitrary;
#[cfg(feature = "passkeys")]
pub use saa_passkeys::passkey::PasskeyCredential;
#[cfg(feature = "secp256r1")]
pub use saa_passkeys::secp256r1::Secp256r1;
#[cfg(feature = "secp256k1")]
pub use saa_curves::secp256k1::Secp256k1;
#[cfg(feature = "ed25519")]
pub use saa_curves::ed25519::Ed25519;



#[saa_derivable(name(CredentialName))]
pub enum Credential {
    Native(Caller),

    #[cfg(feature = "eth_personal")]
    EthPersonalSign(EthPersonalSign),

    #[cfg(feature = "cosmos")]
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





#[saa_type]
pub struct CredentialInfo {
    /// name of the used credential
    pub name: CredentialName,
    /// human readable prefix to encode from a public key
    pub hrp: Option<String>,
    /// extension data
    pub extension: Option<Binary>,
}



pub type CredentialRecord = (CredentialId, CredentialInfo);



#[allow(unused, dead_code)]
#[cfg(feature = "wasm")]
pub fn build_credential(
    record      : CredentialRecord,
    msg         : crate::msgs::SignedDataMsg,
    extension   : Option<Binary>,
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

        #[cfg(feature = "cosmos")]
        CredentialName::CosmosArbitrary => Credential::CosmosArbitrary(CosmosArbitrary {
            pubkey: Binary::from_base64(&id)?,
            message,
            signature,
            hrp: info.hrp,
        }),

        #[cfg(feature = "passkeys")]
        CredentialName::Passkey => {
            use saa_passkeys::passkey::{
                ClientData, PasskeyInfo, PasskeyPayload, 
                utils::base64_to_url
            };
            let stored_info  = info.extension
                .map(|e| saa_common::from_json::<PasskeyInfo>(e).ok() )
                .flatten()
                .ok_or_else(|| saa_common::AuthError::generic("Missing passkey info"))?;
            
            let (origin, other_keys) = match extension
                .map(|e| saa_common::from_json::<PasskeyPayload>(e).ok())
                .flatten()
            {
                Some(payload) => (payload.origin, payload.other_keys),
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
            pubkey: Binary::from_base64(&id)?,
            signature,
            message,
        }),
        #[cfg(feature = "secp256k1")]
        CredentialName::Secp256k1 => Credential::Secp256k1(Secp256k1 {
            pubkey: Binary::from_base64(&id)?,
            signature,
            message,
            hrp: info.hrp,
        }),
        #[cfg(feature = "ed25519")]
        CredentialName::Ed25519 => Credential::Ed25519(Ed25519 {
            pubkey: Binary::from_base64(&id)?,
            signature,
            message,
        }),
    };
    Ok(credential)
}