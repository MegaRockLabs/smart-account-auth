use std::str::FromStr;

use saa_common::Binary;
use smart_account_auth::{Caller, Credential, CredentialName, Secp256k1, Secp256r1, Ed25519};

use crate::vars::{get_cosmos_arbitrary, get_eth_personal, get_passkey};
use strum::IntoDiscriminant; 


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
        &Secp256k1 {
            pubkey: Binary::default(),
            message: Binary::default(),
            signature: Binary::default(),
            hrp: None,
        }.into(), CredentialName::Secp256k1, "secp256k1"
    );
    name_checker(
        &Secp256r1 {
            pubkey: Binary::default(),
            message: Binary::default(),
            signature: Binary::default(),
        }.into(), CredentialName::Secp256r1, "secp256r1"
    );
    name_checker(
        &Ed25519 {
            pubkey: Binary::default(),
            message: Binary::default(),
            signature: Binary::default(),
        }.into(), CredentialName::Ed25519, "ed25519"
    );
}

