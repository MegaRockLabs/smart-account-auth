
#[cfg(feature = "eth_personal")]
pub use saa_auth::eth::EthPersonalSign;
#[cfg(feature = "eth_typed_data")]
pub use saa_auth::eth::{Eip712Types, EthTypedData};
#[cfg(any(feature = "cosmos_arb", feature = "cosmos_arb_addr"))]
pub use saa_auth::cosmos::CosmosArbitrary;
#[cfg(feature = "passkeys")]
pub use saa_passkeys::PasskeyCredential;
#[cfg(feature = "secp256r1")]
pub use saa_passkeys::Secp256r1;
#[cfg(feature = "secp256k1")]
pub use saa_curves::secp256k1::Secp256k1;
#[cfg(feature = "ed25519")]
pub use saa_curves::ed25519::Ed25519;
pub use saa_common::{CredentialId, CredentialName, CredentialAddress, CredentialInfo, CredentialRecord};
pub use crate::caller::Caller;



#[saa_schema::saa_type]
pub enum Credential {
    Native(Caller),
    #[cfg(feature = "eth_personal")]
    EthPersonalSign(EthPersonalSign),
    #[cfg(feature = "eth_typed_data")]
    EthTypedData(EthTypedData),
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


#[allow(unused, dead_code)]
#[cfg(feature = "wasm")]
pub fn build_credential(
    record      : CredentialRecord,
    msg         : crate::msgs::SignedDataMsg,
    payload     : Option<saa_common::PayloadExtension>,
) -> Result<Credential, saa_common::CredentialError> {
    return Err(saa_common::CredentialError::NoneLeft);
    /* 
    let (id, info) = record;
    let message = msg.data;
    let signature = msg.signature;
    let name = info.name;
    
    let credential = match name {

        CredentialName::Native => Credential::Native(Caller(id)),

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

        #[cfg(feature = "eth_personal")]
        CredentialName::EthPersonalSign => Credential::EthPersonalSign(EthPersonalSign {
            message,
            signature,
            signer: id,
        }),

        #[cfg(any(feature = "cosmos_arb", feature = "cosmos_arb_addr"))]
        CredentialName::CosmosArbitrary => Credential::CosmosArbitrary(CosmosArbitrary {
            pubkey: saa_common::Binary::from_base64(&id)?,
            message,
            signature,
            #[cfg(not(feature = "cosmos_arb_addr"))]
            hrp: info.hrp,
            #[cfg(feature = "cosmos_arb_addr")]
            address: info.address
                .ok_or_else(|| saa_common::CredentialError::NoInfoProperty(
                    CredentialName::CosmosArbitrary, "address".into()))?
                .to_string(),
        }),

        #[cfg(feature = "passkeys")]
        CredentialName::Passkey => {
            use saa_common::{InfoExtension, PayloadExtension};
            use saa_passkeys::{ClientData, PasskeyInfo, PasskeyPayload, utils::base64_to_url};

            let Some(InfoExtension::Passkey(info_ext)) = info.extension else {
                return Err(saa_common::CredentialError::NoInfoExt(CredentialName::Passkey))
            };

            let (origin, other_keys) = match payload {
                Some(PayloadExtension::Passkey(PasskeyPayload { 
                    origin, other_keys 
                })) => (origin, other_keys),
                _ => (None, None),
            };

            let client_data = ClientData::new(
                base64_to_url(message.to_base64().as_str()),
                origin.unwrap_or(info_ext.origin),
                info_ext.cross_origin,
                other_keys
            );

            Credential::Passkey(PasskeyCredential {
                id,
                signature,
                client_data,
                pubkey: Some(info_ext.pubkey),
                authenticator_data: info_ext.authenticator_data,
                user_handle: info_ext.user_handle,
            })
        },
        #[cfg(feature = "eth_typed_data")]
        CredentialName::EthTypedData => {
            use saa_auth::eth::{Eip712Domain, EthTypedData};
            use saa_common::{from_json, InfoExtension, PayloadExtension};

            let Some(InfoExtension::EthTypedData(info_ext)) = info.extension else {
                return Err(saa_common::CredentialError::NoInfoExt(CredentialName::EthTypedData))
            };

            let (
                types,
                primary_type,
                domain
            ) = if let Some(PayloadExtension::EthTypedData(pay_ext)) = payload {
                (
                    pay_ext.types,
                    pay_ext.primary_type,
                    pay_ext.domain
                )
            } else {
                (None, None, None)
            };

 
            let types = types
                .ok_or_else(|| saa_common::CredentialError::InvalidProperty(
                    CredentialName::EthTypedData, "types".into(), "Payload is missing or has invalid Eip712 types".into()
                ))?;
            
            let domain = domain
                .ok_or_else(|| saa_common::CredentialError::InvalidProperty(
                    CredentialName::EthTypedData, "domain".into(), "Payload is missing or has invalid Eip712 domain".into()
                ))?;

            Credential::EthTypedData(EthTypedData {
                signer: id,
                types,
                signature,
                domain,
                primary_type: primary_type.ok_or(
                    saa_common::CredentialError::NoInfoProperty(
                        CredentialName::EthTypedData, "primary_type".into()
                    )
                )?,
                message: from_json(&message)
                    .map_err(|e| saa_common::CredentialError::InvalidProperty(
                        CredentialName::EthTypedData, "message".into(), e.to_string()
                    ))?,
                message_property: None,
                cache: Some(info_ext),
                #[cfg(all(feature = "wasm", target_arch = "wasm32"))]
                check_cw2 : None,
            })
        },
      
    };
    
    Ok(credential) */
}


