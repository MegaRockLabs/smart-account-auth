mod ethereum;
mod passkey;

use std::str::FromStr;

use crate::utils::{get_cosmos_arbitrary, get_eth_personal, get_passkey};
use cw_auths::saa_types::{Caller, Ed25519, Credential, CredentialName};
use strum::IntoDiscriminant; 
use saa_common::Binary;


fn name_checker(
    cred: &Credential,
    name: CredentialName,
    str: &str,
) {
    assert!(str == cred.name().to_string() && str == name.to_string());
    let str_name = CredentialName::from_str(str);
    assert!(str_name.is_ok(), "Can't deriving `CredentialName` from {str:?}");
    assert!(name == cred.discriminant() && name == cred.name() && name == str_name.unwrap())
}



#[test]
fn credential_names() {
    name_checker(
        &get_eth_personal().into(), CredentialName::EthPersonalSign, "eth_personal_sign"
    );
    name_checker(
        &get_cosmos_arbitrary().into(), CredentialName::CosmosArbitrary, "cosmos_arbitrary"
    );
    name_checker(
        &get_passkey().into(), CredentialName::Passkey, "passkey"
    );
    name_checker(
        &Caller::from("alice").into(), CredentialName::Native, "native"
    );
    name_checker(
        &Ed25519 {
            pubkey: Binary::default(),
            message: Binary::default(),
            signature: Binary::default(),
        }.into(), CredentialName::Ed25519, "ed25519"
    );
}

